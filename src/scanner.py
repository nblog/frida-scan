#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Frida-based AOB scanner core functionality
"""

import json
import codecs
import argparse
from typing import List, Dict, Any, Optional
from pathlib import Path

from src.models import ScanConfig, ScanResults
from src.exceptions import FridaScanException

from frida_tools.application import ConsoleApplication

class ScannerApplication(ConsoleApplication):
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
            self._exit(1)
        finally:
            if self._script is not None:
                self._script.unload()
                self._script = None
            self._exit(0)


    def _get_builtin_script(self) -> str:
        """Get built-in JavaScript scanner script"""
        # with codecs.open(r"resource/aobscan2.js", encoding='utf-8-sig') as f:
        #     return f.read()
        return \
'''
/* Frida AOB Scanner Script */
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

    /*branch*/call(addr) { return this.mem32(addr.add(1)); };

    aobscan(pattern) {
        const matches = [];
        for (const m of this.module().enumerateRanges('--x')) {
            matches.push(...Memory.scanSync(m.base, m.size, pattern));
        }
        return matches;
    };
}

var addr = new addr_transform();

rpc.exports = {

    modulepath(module_name='') {
        return Process.getModuleByName(module_name || addr.module().name).path;
    },

    searchmodule(module_name) {
        addr = new addr_transform(module_name);
        return true;
    },

    aobscan(vJson) {
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
                return ordinals[number] || `${number}th`;
            }
            console.warn(`aobscan: \"${name}\" matches to ${matches.length}, using the ${toOrdinal(aobData.selected)}.`);
        }

        let match = ptr(matches[aobData.selected - 1].address).add(aobData.offset);
        if (match.isNull()) {
            console.error(`aobscan: \"${name}\" not found.`);
            return 0;
        }

        if (null != aobData.equal) {
            for (let i = 0; i <= aobData.equal.range;) {
                const info = Instruction.parse(match);

                if (info.toString().toLowerCase().includes(aobData.equal.cmd.toLowerCase())) {
                    match = info.address;
                    break;
                }

                match = info.next; i += info.size;
            }
        }

        return Number(addr[aobData.mode](match));
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
            "selected": Number(vJson["selected"]),
            "offset": Number(vJson["offset"]),
            "equal": this.EQUAL(vJson["equal"]),
        };
    }
}
'''
    
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
            with codecs.open(config_path, encoding='utf-8-sig') as f:
                config_data = json.load(f)
            config = ScanConfig(**config_data)
        except Exception as e:
            raise FridaScanException(f"Failed to load config: {e}")
        
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
            
            # Check for duplicate names
            if pattern.name in processes_:
                raise FridaScanException(f"Duplicate pattern name: {pattern.name}")
            
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
    
    def _eval_expr(self, expr: str, context: Dict[str, int]) -> int:
        """Safely evaluate mathematical expression"""
        try:
            return int(eval(expr, {"__builtins__": {}}, context))
        except Exception as e:
            raise FridaScanException(f"Failed to evaluate expression '{expr}': {e}")
    
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
                raise FridaScanException(f"Failed to find AOB pattern: {scan_data['pattern']}")
            return result
        except Exception as e:
            raise FridaScanException(f"AOB scan error: {e}")
    
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


scanner = ScannerApplication()
scanner.run()