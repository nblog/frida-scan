
# Frida-Scan

A powerful AOB (Array of Bytes) scanner powered by [Frida](https://frida.re/) for memory pattern scanning.

## Features

- 🔍 **Advanced Pattern Scanning**: Support for complex byte patterns with wildcards
- 📝 **Flexible Configuration**: JSON-based configuration with expression evaluation
- 🔧 **Instruction Matching**: Advanced instruction equality checking with configurable ranges
- 📦 **Easy Installation**: Install and run with `uvx` or `pip`
- 🔄 **Multiple Matches**: Handle multiple pattern matches with selection options

## Installation

### Using uvx (Recommended)

```bash
uvx --from frida-scan@git+https://github.com/nblog/frida-scan.git frida-scan -n notepad.exe config.json.example
```

### Scan Modes

- **`rva`**: Relative Virtual Address (offset from module base)
- **`va`**: Virtual Address (converts an RVA to an absolute address)
- **`imm8/16/32/64/128`**: Read an unsigned immediate value at the match address
- **`deref8/16/32/64/128`**: Dereference a pointer at the match address, then read the value
- **`rel32`**: Resolve an x86 rel32 displacement field into a target RVA
- **`rel32CallTarget`**: Resolve a `CALL`/`JMP rel32` instruction (single-byte opcode `E8`/`E9`) into its target RVA; `offset` must point at the opcode byte itself, not at the displacement field

### Common Issues

1. **Process not found**: Ensure the process is running and the name/PID is correct
2. **Pattern not found**: Verify the byte pattern is correct and the target module is loaded
3. **Permission denied**: Run with administrator privileges on Windows
4. **Multiple matches**: Use the `selected` field to choose which match to use
5. **Invalid match pattern**: Frida's `MatchPattern` rejects a wildcard (`??`) as the last byte of a pattern; add one more concrete byte after any trailing `??`

## License

This project is licensed under the WTFPL License. Dependencies are under their respective licenses.