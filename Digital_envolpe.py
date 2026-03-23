"""
Digital Envelope - Hybrid Encryption (RSA + AES-256-CBC)
Suitable for large messages / files

Features:
- RSA-OAEP for key encapsulation (2048-bit)
- AES-256-CBC + PKCS7 padding for content 
- Base64 encoding for transmission  
- Supports text input or file reading
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
import os
import base64
import json
from pathlib import Path
import sys

# ────────────────────────────────────────────────
#  Colors for nicer console output (Windows compatible)
# ────────────────────────────────────────────────
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def cprint(color, *args, **kwargs):
    print(color + " ".join(map(str, args)) + Colors.ENDC, **kwargs)

# ────────────────────────────────────────────────
#                 Core Functions
# ────────────────────────────────────────────────

def generate_recipient_keys(bits=2048):
    cprint(Colors.OKBLUE, "Generating 2048-bit RSA key pair for recipient...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    public_key = private_key.public_key()
    return private_key, public_key

def read_message(source):
    """Read message from text or file"""
    if Path(source).is_file():
        cprint(Colors.OKBLUE, f"Reading file: {source}")
        with open(source, "rb") as f:
            data = f.read()
        mode = "binary"
    else:
        cprint(Colors.OKBLUE, "Using direct text input")
        data = source.encode("utf-8")
        mode = "text"
    return data, mode

def create_envelope(plaintext: bytes, public_key) -> dict:
    """Create digital envelope for large content"""
    # ── Session key & IV ───────────────────────────────
    session_key = os.urandom(32)   # AES-256
    iv = os.urandom(16)

    # ── Encrypt content ────────────────────────────────
    padder = PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    # ── Encrypt session key with RSA-OAEP ──────────────
    encrypted_key = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return {
        "version": "1.0",
        "alg_key": "RSA-OAEP-SHA256",
        "alg_content": "AES-256-CBC",
        "encrypted_key": base64.b64encode(encrypted_key).decode('ascii'),
        "iv": base64.b64encode(iv).decode('ascii'),
        "ciphertext": base64.b64encode(ciphertext).decode('ascii'),
        "size_original": len(plaintext),
        "size_ciphertext": len(ciphertext)
    }

def open_envelope(envelope: dict, private_key) -> bytes:
    """Recipient opens the envelope"""
    encrypted_key = base64.b64decode(envelope["encrypted_key"])
    iv = base64.b64decode(envelope["iv"])
    ciphertext = base64.b64decode(envelope["ciphertext"])

    # Decrypt session key
    session_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decrypt content
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()

    return plaintext

def print_envelope_summary(envelope, title="DIGITAL ENVELOPE"):
    print("\n" + "═" * 70)
    print(f" {Colors.BOLD}{title}{Colors.ENDC} ".center(70, "═"))
    print("═" * 70)

    data = {
        "Version": envelope["version"],
        "Key Encapsulation": envelope["alg_key"],
        "Content Encryption": envelope["alg_content"],
        "Original Size": f"{envelope['size_original']:,} bytes",
        "Ciphertext Size": f"{envelope['size_ciphertext']:,} bytes",
        "Encrypted Key (base64, first 64)": envelope["encrypted_key"][:64] + "...",
        "IV (base64)": envelope["iv"],
    }

    for k, v in data.items():
        print(f" {Colors.OKBLUE}{k:<18}{Colors.ENDC} : {v}")

    print("═" * 70 + "\n")

# ────────────────────────────────────────────────
#                     MAIN DEMO
# ────────────────────────────────────────────────

def main():
    print("\n" + Colors.HEADER + "Digital Envelope Demo (Hybrid Encryption)" + Colors.ENDC)
    print("Supports large messages / files\n")

    # 1. Generate recipient keys (in real life: done once)
    priv_key, pub_key = generate_recipient_keys()

    # 2. Get input from user
    print(Colors.WARNING + "Enter message or path to file (press Enter twice to finish text input):" + Colors.ENDC)
    lines = []
    while True:
        line = input()
        if line == "":
            break
        lines.append(line)
    user_input = "\n".join(lines).strip()

    if not user_input:
        print(Colors.FAIL + "No input provided. Exiting." + Colors.ENDC)
        return

    plaintext, input_mode = read_message(user_input)

    # 3. Create envelope
    print("\n" + Colors.OKGREEN + "Encrypting..." + Colors.ENDC)
    envelope = create_envelope(plaintext, pub_key)

    # 4. Show result
    print_envelope_summary(envelope, "ENVELOPE CREATED (SENDER SIDE)")

    # 5. Simulate receiver
    print(Colors.OKGREEN + "Decrypting (Recipient side)..." + Colors.ENDC)
    try:
        recovered = open_envelope(envelope, priv_key)
        print("\n" + Colors.BOLD + "Recovered content:" + Colors.ENDC)

        if input_mode == "text":
            try:
                text = recovered.decode("utf-8")
                print("─" * 70)
                print(text)
                print("─" * 70)
            except UnicodeDecodeError:
                print(Colors.WARNING + "[Binary content – showing first 200 bytes in hex]" + Colors.ENDC)
                print(recovered[:200].hex())
        else:
            print(Colors.WARNING + "[Binary file recovered – not displaying full content]" + Colors.ENDC)
            print(f"Size: {len(recovered):,} bytes")
            print("First 32 bytes (hex):", recovered[:32].hex())

        print("\n" + Colors.OKGREEN + "✓ Success – content recovered correctly" + Colors.ENDC)

    except Exception as e:
        print(Colors.FAIL + "Decryption failed!" + Colors.ENDC)
        print(str(e))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n" + Colors.WARNING + "Interrupted by user." + Colors.ENDC)
    except Exception as e:
        print(Colors.FAIL + "Unexpected error:" + Colors.ENDC)
        print(str(e))