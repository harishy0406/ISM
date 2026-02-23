from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
import os
import base64

def generate_rsa_keys(key_size=512):
    """Generate RSA private and public keys."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key = private_key.public_key()
    return private_key, public_key

def sign_message(private_key, message):
    """Sign the message by hashing it and encrypting the hash with the private key."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message.encode('utf-8'))
    hash_value = digest.finalize()
    
    signature = private_key.sign(
        hash_value,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature, hash_value

def encrypt_message(message):
    """Encrypt the message using a symmetric AES key."""
    aes_key = os.urandom(32)  # 256-bit AES key
    iv = os.urandom(16)       # Initialization vector
    
    padder = PKCS7(128).padder()
    padded_data = padder.update(message.encode('utf-8')) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(padded_data) + encryptor.finalize()
    
    return aes_key, iv, encrypted_message

def encrypt_aes_key(public_key, aes_key):
    """Encrypt the symmetric AES key using the public key."""
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_aes_key

def decrypt_aes_key(private_key, encrypted_aes_key):
    """Decrypt the symmetric AES key using the private key."""
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key

def decrypt_message(aes_key, iv, encrypted_message):
    """Decrypt the message using the symmetric AES key."""
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted_message) + decryptor.finalize()
    
    unpadder = PKCS7(128).unpadder()
    decrypted_message = unpadder.update(decrypted_padded) + unpadder.finalize()
    
    return decrypted_message.decode('utf-8')

def verify_signature(public_key, signature, hash_value):
    """Verify the signature using the public key."""
    try:
        public_key.verify(
            signature,
            hash_value,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False

def main():
    # Step 3: Generate set of PKC keys (RSA 512-bit)
    print("Generating RSA key pair (512 bits)...")
    private_key, public_key = generate_rsa_keys(512)
    
    # Take input from user
    message = input("Enter the message to sign and encrypt: ")
    
    # Step 1: Message with hash code (sign the hash using private key)
    print("\nSigning the message...")
    signature, original_hash = sign_message(private_key, message)
    
    # Step 2: Message encryption using symmetric key
    print("Encrypting the message with symmetric key...")
    aes_key, iv, encrypted_message = encrypt_message(message)
    
    # Encrypt the symmetric key with public key (hybrid aspect)
    print("Encrypting the symmetric key with public key...")
    encrypted_aes_key = encrypt_aes_key(public_key, aes_key)
    
    # For demonstration: Decrypt and verify
    print("\nDemonstrating decryption and verification...")
    decrypted_aes_key = decrypt_aes_key(private_key, encrypted_aes_key)
    decrypted_message = decrypt_message(decrypted_aes_key, iv, encrypted_message)
    
    # Recompute hash of decrypted message
    digest = hashes.Hash(hashes.SHA256())
    digest.update(decrypted_message.encode('utf-8'))
    decrypted_hash = digest.finalize()
    
    is_valid = verify_signature(public_key, signature, decrypted_hash)
    
    # Display results in a formatted way
    print("\n" + "=" * 50)
    print("Original Message:".ljust(25) + message)
    print("Decrypted Message:".ljust(25) + decrypted_message)
    print("Signature Valid:".ljust(25) + str(is_valid))
    print("Encrypted Message:".ljust(25) + base64.b64encode(encrypted_message).decode('utf-8')[:50] + "... (truncated)")
    print("Signature:".ljust(25) + base64.b64encode(signature).decode('utf-8')[:50] + "... (truncated)")
    print("Encrypted AES Key:".ljust(25) + base64.b64encode(encrypted_aes_key).decode('utf-8')[:50] + "... (truncated)")
    print("IV:".ljust(25) + base64.b64encode(iv).decode('utf-8'))
    print("=" * 50)

if __name__ == "__main__":
    main()