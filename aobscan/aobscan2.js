
/* https://github.com/nblog/my-fridajs-example/blob/dev/aobscan.ts */

class addr_transform {

    #moduleName = ''

    constructor(moduleName='') {
        this.#moduleName = moduleName || Process.enumerateModules()[0].name;
    };

    module() { return Process.getModuleByName(this.#moduleName); };

    base() { return this.module().base; };

    va(rva) { return this.base().add(rva); };

    rva(va) { return Number(va.sub(this.base()).and(0x7fffffff)); };

    imm8(addr) { return addr.readU8(); };

    imm16(addr) { return addr.readU16(); };

    imm32(addr) { return addr.readU32(); };

    imm64(addr) { return addr.readU64(); }

    mem32(addr) { return this.rva(addr.add(addr.readS32()).add(4)); };

    call(addr) { return this.mem32(addr.add(1)); };

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

    modulepath(module_name='') {
        return (module_name ? Process.getModuleByName(module_name) : Process.enumerateModules()[0]).path;
    },

    searchmodule(module_name) {
        addr = new addr_transform(module_name);
    },

    aobscan(vJson) {
        let aob = this.AOBOBJECT(vJson);

        let matches = addr.aobscan(aob.pattern);

        const name = aob.note || aob.name;

        if (0 == matches.length) {
            console.error(`aobscan: \"${name}\" not found.`);
            return 0;
        }

        if (1 < matches.length) {
            console.warn(`aobscan: \"${name}\" matched ${matches.length} times, use the first one.`);
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
            "cmd": String(vJson["cmd"]),
            "range": Number(vJson["range"])
        };
    },
    AOBOBJECT(vJson) {
        if (null == vJson) return null;
        return {
            "name": String(vJson["name"]),
            "note": String(vJson["note"]),

            "mode": String(vJson["mode"]),
            "pattern": String(vJson["pattern"]),
            "offset": Number(vJson["offset"]),
            "equal": this.EQUAL(vJson["equal"]),
        };
    }
}
