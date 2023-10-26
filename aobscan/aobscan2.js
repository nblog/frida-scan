
/* https://github.com/nblog/my-fridajs-example/blob/dev/aobscan.ts */

class addr_transform {

    #moduleName = ''

    constructor(moduleName='') {
        this.#moduleName = moduleName || Process.enumerateModules()[0].name;
    };

    module() { return Process.getModuleByName(this.#moduleName); };

    base() { return this.module().base; };

    va(rva) { return this.base().add(rva); };

    imm8(addr) { return addr.readS8(); };

    imm16(addr) { return addr.readS16(); };

    imm32(addr) { return addr.readS32(); };

    imm64(addr) { return addr.readS64(); }

    rel32(addr) { return addr.add(this.imm32(addr)).add(4) };

    rva(va) { return Number(va.sub(this.base()).and(0x7fffffff)); };

    call(addr) {
        addr = addr.add(1);
        return this.rva(this.rel32(addr));
    };

    equal(addr, cmd='call') {
        let info = Instruction.parse(addr);
        return [ info.mnemonic, info.opStr ].join(' ').includes(cmd.toLowerCase());
    };

    aobscan(pattern) {
        for (const m of this.module().enumerateRanges('--x')) {
            let match = Memory.scanSync(m.base, m.size, pattern);
            if (0 < match.length) return match;
        }
        return [];
    };
}


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
