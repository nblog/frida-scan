
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
# Run directly without installation
uvx --from frida-scan@git+https://github.com/nblog/frida-scan.git frida-scan -n process <config.json> <output.json>
```

### Scan Modes

- **`rva`**: Relative Virtual Address
- **`va`**: Virtual Address
- **`call`**: Call target address
- **`mem32`**: Memory dereference (32-bit)
- **`imm8/16/32/64`**: Immediate values (8/16/32/64 bit)

### Common Issues

1. **Process not found**: Ensure the process is running and the name/PID is correct
2. **Pattern not found**: Verify the byte pattern is correct and the target module is loaded
3. **Permission denied**: Run with administrator privileges on Windows
4. **Multiple matches**: Use the `selected` field to choose which match to use

## License

This project is licensed under the WTFPL License. Dependencies are under their respective licenses.