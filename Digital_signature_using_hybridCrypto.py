from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import base64

# ---------- Helper Padding Functions ----------
def pad(data):
    pad_len = 16 - len(data) % 16
    return data + bytes([pad_len]) * pad_len

def unpad(data):
    return data[:-data[-1]]

# ---------- MAIN PROGRAM ----------
print("\n========== HYBRID DIGITAL SIGNATURE SYSTEM ==========\n")

# User input
message = input("Enter your message: ").encode()

# ---------------------------------------------------
# STEP 3: Generate PKC (RSA) Keys - 1024 bits
# ---------------------------------------------------
rsa_key = RSA.generate(1024)
private_key = rsa_key
public_key = rsa_key.publickey()

print("\n--- RSA Keys Generated (512 bits) ---")
print("Public Key:\n", public_key.export_key().decode())
print("Private Key:\n", private_key.export_key().decode())

# ---------------------------------------------------
# STEP 1: Hash Message + Digital Signature
# ---------------------------------------------------
hash_msg = SHA256.new(message)
signature = pkcs1_15.new(private_key).sign(hash_msg)

print("\n--- Message Hash (SHA-256) ---")
print(hash_msg.hexdigest())

print("\n--- Digital Signature ---")
print(base64.b64encode(signature).decode())

# ---------------------------------------------------
# STEP 2: Symmetric Encryption (AES)
# ---------------------------------------------------
aes_key = get_random_bytes(16)
aes_cipher = AES.new(aes_key, AES.MODE_CBC)
ciphertext = aes_cipher.encrypt(pad(message))

print("\n--- AES Symmetric Key ---")
print(base64.b64encode(aes_key).decode())

print("\n--- Encrypted Message (AES) ---")
print(base64.b64encode(ciphertext).decode())

# ---------------------------------------------------
# Encrypt AES Key using RSA Public Key
# ---------------------------------------------------
rsa_cipher = PKCS1_OAEP.new(public_key)
encrypted_aes_key = rsa_cipher.encrypt(aes_key)

print("\n--- AES Key Encrypted Using RSA Public Key ---")
print(base64.b64encode(encrypted_aes_key).decode())

# ===================================================
# RECEIVER SIDE
# ===================================================
print("\n========== RECEIVER SIDE ==========")

# Decrypt AES Key
rsa_dec = PKCS1_OAEP.new(private_key)
decrypted_aes_key = rsa_dec.decrypt(encrypted_aes_key)

# Decrypt Message
aes_dec = AES.new(decrypted_aes_key, AES.MODE_CBC, aes_cipher.iv)
decrypted_msg = unpad(aes_dec.decrypt(ciphertext))

# Verify Signature
hash_recv = SHA256.new(decrypted_msg)

try:
    pkcs1_15.new(public_key).verify(hash_recv, signature)
    status = "VALID"
except:
    status = "INVALID"

print("\n--- Decrypted Message ---")
print(decrypted_msg.decode())

print("\n--- Signature Verification ---")
print(status)

print("\n========== PROCESS COMPLETED SUCCESSFULLY ==========\n")