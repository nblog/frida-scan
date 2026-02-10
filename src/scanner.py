#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Frida-based AOB scanner core functionality
"""

import ast
import json
import operator
import argparse
from typing import List, Dict, Any, Optional
from pathlib import Path

from .models import ScanConfig, ScanResults
from .exceptions import FridaScanException, ConfigurationError, ScanError

from frida_tools.application import ConsoleApplication

class ScannerApplication(ConsoleApplication):

    def _get_builtin_script(self) -> str:
        """Get built-in JavaScript scanner script (pure JavaScript, no TypeScript)"""
        # Converted from TypeScript to pure JavaScript for QJS compatibility
        # Source: https://github.com/nblog/my-fridajs-example/raw/refs/heads/dev/aobscan.ts
        return \
'''
class addr_transform {
    constructor(moduleName, version) {
        this.#version = version || 'unknown';
        this.#moduleName = moduleName || Process.enumerateModules()[0].name;
    }

    module() {
        return Process.getModuleByName(this.#moduleName);
    }

    base() {
        return this.module().base;
    }

    va(rva) {
        return this.base().add(rva);
    }

    rva(va) {
        return va.sub(this.base()).toUInt32();
    }

    /** little-endian 128-bit integer from ArrayBuffer */
    #toInt128(arr) {
        if (!arr || arr.byteLength < 16) {
            throw new Error(`toInt128: invalid buffer (got ${arr?.byteLength ?? 'null'})`);
        }
        const view = new DataView(arr);
        const lo = view.getBigUint64(0, true);
        const hi = view.getBigUint64(8, true);
        return (hi << 64n) | lo;
    }

    /** read unsigned immediate: number (8/16/32), UInt64 (64), bigint (128) */
    imm8(addr, immOffset) {
        immOffset = immOffset || 0;
        return addr.add(immOffset).readU8();
    }
    imm16(addr, immOffset) {
        immOffset = immOffset || 0;
        return addr.add(immOffset).readU16();
    }
    imm32(addr, immOffset) {
        immOffset = immOffset || 0;
        return addr.add(immOffset).readU32();
    }
    imm64(addr, immOffset) {
        immOffset = immOffset || 0;
        return addr.add(immOffset).readU64();
    }
    imm128(addr, immOffset) {
        immOffset = immOffset || 0;
        return this.#toInt128(addr.add(immOffset).readByteArray(16));
    }

    /** dereference pointer at addr, then read value. throws on NULL pointer. */
    deref8(addr) {
        return this.#derefSafe(addr).readU8();
    }
    deref16(addr) {
        return this.#derefSafe(addr).readU16();
    }
    deref32(addr) {
        return this.#derefSafe(addr).readU32();
    }
    deref64(addr) {
        return this.#derefSafe(addr).readU64();
    }
    deref128(addr) {
        return this.#toInt128(this.#derefSafe(addr).readByteArray(16));
    }

    #derefSafe(addr) {
        const p = addr.readPointer();
        if (p.isNull()) {
            throw new Error(`deref: NULL pointer at ${addr}`);
        }
        return p;
    }

    /** x86 rel32 resolve: addr points to the 4-byte displacement field, returns RVA of target.
     *  target = addr + 4 (field size) + *addr (signed displacement) */
    rel32(addr) {
        return this.rva(addr.add(4).add(addr.readS32()));
    }

    /** resolve CALL/JMP rel32 target from instruction start (single-byte opcode: E8/E9).
     *  NOT suitable for 2-byte opcodes (e.g. 0F 8x, FF 15). */
    rel32CallTarget(addr) {
        return this.rel32(addr.add(1));
    }

    /** scan module memory for byte pattern. protection filter defaults to executable ('--x'). */
    aobscan(pattern, protection) {
        protection = protection || '--x';
        const matches = [];
        for (const m of this.module().enumerateRanges(protection)) {
            matches.push(...Memory.scanSync(m.base, m.size, pattern));
        }
        return matches;
    };
}
''' + \
'''
var addr = new addr_transform();

rpc.exports = {
    modulepath: function(module_name) {
        module_name = module_name || '';
        return Process.getModuleByName(module_name || addr.module().name).path;
    },

    searchmodule: function(module_name) {
        addr = new addr_transform(module_name);
        return true;
    },

    aobscan: function(vJson) {
        let aobData = this.AOBOBJECT(vJson);
        let matches = addr.aobscan(aobData.pattern);
        const name = aobData.note || aobData.name;

        if (0 == matches.length) {
            console.error(`aobscan: \"${name}\" not found.`);
            return 0;
        }

        if (1 < matches.length) {
            function toOrdinal(number) {
                const ordinals = ["", "1st", "2nd", "3rd"];
                return ordinals[number] || (number + "th");
            }
            console.warn(`aobscan: \"${name}\" matches to ${matches.length}, using the ${toOrdinal(aobData.selected)}.`);
        }

        let match = ptr(matches[aobData.selected - 1].address).add(aobData.offset);
        if (match.isNull()) {
            console.error(`aobscan: \"${name}\" not found.`);
            return 0;
        }

        if (null != aobData.equal) {
            let found = false;
            for (let i = 0; i <= aobData.equal.range;) {
                const info = Instruction.parse(match);

                if (info.toString().toLowerCase().includes(aobData.equal.cmd.toLowerCase())) {
                    match = info.address;
                    found = true;
                    break;
                }

                match = info.next;
                i += info.size;
            }
            if (!found) {
                console.error(`aobscan: \"${name}\" equal instruction \"${aobData.equal.cmd}\" not found within range ${aobData.equal.range}.`);
                return 0;
            }
        }

        return Number(addr[aobData.mode](match));
    },

    EQUAL: function(vJson) {
        if (null == vJson) return null;
        return {
            "cmd": String(vJson["cmd"]),
            "range": Number(vJson["range"])
        };
    },

    AOBOBJECT: function(vJson) {
        if (null == vJson) return null;
        return {
            "name": String(vJson["name"] ?? ""),
            "note": String(vJson["note"] ?? ""),

            "mode": String(vJson["mode"]),
            "pattern": String(vJson["pattern"]),
            "selected": Number(vJson["selected"] ?? 1),
            "offset": Number(vJson["offset"] ?? 0),
            "equal": this.EQUAL(vJson["equal"])
        };
    }
};
'''

    def _needs_target(self) -> bool:
        return True
    
    def _usage(self) -> str:
        return "%(prog)s [options] Config.json [--output Output.json]"
    
    def _initialize(self, parser: argparse.ArgumentParser, options: argparse.Namespace, args: List[str]) -> None:
        self._config_file = options.config_file
        self._output_file = options.output_file
    
    def _add_options(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            'config_file',
            type=Path,
            help='JSON file containing scan patterns'
        )
        parser.add_argument(
            '--output',
            dest='output_file',
            type=Path,
            default=Path('output.json'),
            help='Output file for scan results (JSON format, default: output.json)'
        )

    def _on_message(self, message: Dict[str, Any], data: Any) -> None:
        """Handle messages from Frida script"""
        if message['type'] == 'error':
            print(f"[Frida Error] {message['description']}")

    def _start(self) -> None:
        _exit_code = 0
        self._script = None
        try:
            assert self._session is not None
            self._script = self._session.create_script(
                name="scanner",
                source=self._get_builtin_script(),
                runtime=self._runtime)
            self._script.on("message", self._on_message)
            self._on_script_created(self._script)
            self._script.load()
            
            results = self.scan_from_config(self._config_file)
            self.export_results(results, self._output_file)
        except Exception as e:
            self._update_status(f"Failed to load script: {e}")
            _exit_code = 1
        finally:
            if self._script is not None:
                self._script.unload()
                self._script = None
            self._exit(_exit_code)


    def export_results(self, results: ScanResults, output_path: str) -> None:
        """
        Export scan results to JSON file
        
        Args:
            results: ScanResults object
            output_path: Output file path
        """
        export_data = dict(results.results)
        if results.version:
            export_data["#version"] = results.version
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
    
    def scan_from_config(self, config_path: str) -> ScanResults:
        """
        Scan using configuration file
        
        Args:
            config_path: Path to JSON configuration file
            
        Returns:
            ScanResults object containing scan results
        """
        # Load configuration
        try:
            with open(config_path, encoding='utf-8-sig') as f:
                config_data = json.load(f)
            config = ScanConfig(**config_data)
        except Exception as e:
            raise ConfigurationError(f"Failed to load config: {e}")
        
        return self._scan(config)
    
    def _scan(self, config: ScanConfig) -> ScanResults:
        """
        Execute scan based on configuration
        
        Args:
            config: ScanConfig object
            
        Returns:
            ScanResults object containing scan results
        """
        processes_: Dict[str, int] = {}
        
        # Set target module if specified
        if config.module:
            self._change_module(config.module)
        
        # Process each pattern
        for pattern in config.patterns:
            if not pattern.name:
                continue
            
            # Check for reserved and duplicate names
            if pattern.name.startswith("#"):
                raise ConfigurationError(f"Pattern name cannot start with '#' (reserved): {pattern.name}")
            if pattern.name in processes_:
                raise ConfigurationError(f"Duplicate pattern name: {pattern.name}")
            
            # Set default value
            processes_[pattern.name] = self._eval_expr(pattern.value or "0", processes_)
            
            # Process AOB scans for this pattern
            if pattern.aob:
                for aob in pattern.aob:
                    # Evaluate offset expression
                    offset = self._eval_expr(aob.offset or "0", processes_)
                    
                    # Prepare scan data
                    scan_data = {
                        "name": pattern.name,
                        "note": pattern.note or "",

                        "mode": aob.mode,
                        "pattern": aob.pattern,
                        "selected": aob.selected or 1,
                        "offset": offset,
                        "equal": aob.equal.model_dump() if aob.equal else None
                    }
                    
                    # Execute scan
                    result = self._aobscan(scan_data)
                    if result:
                        processes_[pattern.name] = result
                        break  # Use first successful match
        
        # Get program version
        version = self._get_program_version(config.module or "")
        
        return ScanResults(results=processes_, version=version)
    
    # Supported operators for safe expression evaluation
    _SAFE_OPS = {
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.Mult: operator.mul,
        ast.FloorDiv: operator.floordiv,
        ast.Mod: operator.mod,
        ast.BitAnd: operator.and_,
        ast.BitOr: operator.or_,
        ast.BitXor: operator.xor,
        ast.LShift: operator.lshift,
        ast.RShift: operator.rshift,
        ast.USub: operator.neg,
        ast.UAdd: operator.pos,
    }

    def _eval_expr(self, expr: str, context: Dict[str, int]) -> int:
        """Safely evaluate arithmetic expression (no arbitrary code execution)"""
        try:
            tree = ast.parse(expr.strip(), mode='eval')
            return int(self._eval_node(tree.body, context))
        except FridaScanException:
            raise
        except Exception as e:
            raise FridaScanException(f"Failed to evaluate expression '{expr}': {e}")

    def _eval_node(self, node: ast.AST, context: Dict[str, int]) -> int:
        """Recursively evaluate an AST node with only safe arithmetic operations"""
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return int(node.value)
        if isinstance(node, ast.Name) and node.id in context:
            return context[node.id]
        if isinstance(node, ast.UnaryOp):
            op_fn = self._SAFE_OPS.get(type(node.op))
            if op_fn is None:
                raise FridaScanException(f"Unsupported unary operator: {type(node.op).__name__}")
            return op_fn(self._eval_node(node.operand, context))
        if isinstance(node, ast.BinOp):
            op_fn = self._SAFE_OPS.get(type(node.op))
            if op_fn is None:
                raise FridaScanException(f"Unsupported binary operator: {type(node.op).__name__}")
            return op_fn(self._eval_node(node.left, context), self._eval_node(node.right, context))
        raise FridaScanException(f"Unsupported expression node: {type(node).__name__}")
    
    def _change_module(self, module: str) -> None:
        """Change target module"""
        assert self._script is not None, "Script not loaded"
        try:
            result = self._script.exports_sync.searchmodule(module)
            if not result:
                raise FridaScanException(f"Module '{module}' not found")
        except Exception as e:
            raise FridaScanException(f"Failed to change module to '{module}': {e}")
    
    def _aobscan(self, scan_data: Dict[str, Any]) -> int:
        """Execute AOB scan"""
        assert self._script is not None, "Script not loaded"
        try:
            result = self._script.exports_sync.aobscan(scan_data)
            if result is None:
                raise ScanError(f"Failed to find AOB pattern: {scan_data['pattern']}")
            return result
        except ScanError:
            raise
        except Exception as e:
            raise ScanError(f"AOB scan error: {e}")
    
    def _get_program_version(self, module: str = "") -> Optional[str]:
        """Get program version information"""
        try:
            import sys
            if sys.platform == "win32":
                import win32api
                target = self._script.exports_sync.modulepath(module)
                info = win32api.GetFileVersionInfo(target, "\\")
                ms, ls = info['FileVersionMS'], info['FileVersionLS']
                return f'{win32api.HIWORD(ms)}.{win32api.LOWORD(ms)}.{win32api.HIWORD(ls)}.{win32api.LOWORD(ls)}'
        except Exception:
            pass
        return None


def main():
    """Console script entry point"""
    scanner = ScannerApplication()
    scanner.run()

if __name__ == "__main__":
    main()