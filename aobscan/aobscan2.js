

class addr_transform {

    #moduleName = Process.enumerateModules()[0].name;

    constructor(moduleName="") {
        if (moduleName.length) this.#moduleName = moduleName;
    };

    module() {
        return Process.getModuleByName(this.#moduleName);
    };

    base() { return this.module().base; };

    va(rva) { return this.base().add(rva); };

    rva(va) { return Number( va.sub(this.base()).and(0xffffffff) ); };

    imm8(addr) { return addr.readU8(); };

    imm32(addr) { return addr.readU32(); };

    imm64(addr) { return addr.readU64(); }


    mem(addr) {
        let absValue = this.imm32(addr);
        return 4 == Process.pointerSize ? absValue : 
        ( this.rva(addr) + absValue + 4 );
    };

    call(addr) {
        let absValue = this.rva(addr) + this.imm32( addr.add(1) ) + 5;
        return ( absValue & 0xffffffff );
    };

    equal(addr, cmd="call") {
        let info = Instruction.parse( addr );
        return [ info.mnemonic, info.opStr ].join(" ").includes( cmd.toLowerCase() );
    };

    aobscan(pattern) {
        let matches = [];
        this.module().enumerateRanges("--x").forEach(function(range) {
            Memory.scanSync(range.base, range.size, pattern).forEach(function(match) {
                matches.push(match);
            });
        });
        return matches;
    };
}


/* https://github.com/nblog/my-fridajs-example/blob/dev/aobscan.ts */
var addr = new addr_transform();

rpc.exports = {

    searchmodule(module_name) {
        addr = new addr_transform(module_name);
    },

    aobscan(vJson) {
        let aob = this.AOBOBJECT(vJson);

        let matches = addr.aobscan(aob.pattern);

        if (0 == matches.length) {
            console.error(`aobscan: ${aob.note} not found.`);
            return 0;
        }

        if (1 < matches.length) {
            console.warn(`aobscan: ${aob.note} matched ${matches.length} times, use the first one.`);
        }

        let match = ptr(matches[0].address).add(aob.offset);

        if (null != aob.equal) {
            let rematch = match;
            let range = aob.equal.range;
            for (let i = -range; i <= range; i++) {
                rematch = match.add(i);
                if (addr.equal(rematch, aob.equal.cmd)) {
                    match = rematch; break;
                }
            }
        }

        return Number(addr[aob.mode](match));
    },


    EQUAL(vJson) {
        if (null == vJson) return null;
        return {
            "range": Number(vJson["range"]),
            "cmd": String(vJson["cmd"])
        };
    },
    AOBOBJECT(vJson) {
        if (null == vJson) return null;
        return {
            "note": String(vJson["note"]),
            "offset": Number(vJson["offset"]),
            "mode": String(vJson["mode"]),
            "pattern": String(vJson["pattern"]),
            "equal": this.EQUAL(vJson["equal"]),
        };
    }
}