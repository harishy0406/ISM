# Linear Public Key Cryptography:
import random
import secrets

# ---------- Miller-Rabin Primality Test ----------
def is_prime(n, k=10):
    if n < 2:
        return False
    for p in [2, 3, 5, 7, 11]:
        if n % p == 0:
            return n == p

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


# ---------- Generate Large Prime ----------
def gen_prime(bits):
    while True:
        n = secrets.randbits(bits)
        n |= (1 << bits - 1) | 1
        if is_prime(n):
            return n


# ---------- Convert Text to Number ----------
def text_to_number(text):
    return int.from_bytes(text.encode('utf-8'), 'big')


# ---------- Convert Number to Text ----------
def number_to_text(num):
    byte_len = (num.bit_length() + 7) // 8
    return num.to_bytes(byte_len, 'big').decode('utf-8')

print("\n===Linear Public Key Cryptography===\n")
# ---------- Key Generation ----------
bits = int(input("Enter key size in bits (128 / 256 / 512): "))

p = gen_prime(bits)
q = gen_prime(bits)

n = p * q
phi = (p - 1) * (q - 1)

e = 65537
d = pow(e, -1, phi)

print("\nPublic Key (e, n):")
print(e)
print(n)

print("\nPrivate Key (d, n):")
print(d)
print(n)


# ---------- Message Input ----------

msg = input("\nEnter message (number / text / special chars): ")

# Detect numeric or text
if msg.isdigit():
    msg_num = int(msg)
else:
    msg_num = text_to_number(msg)

if msg_num >= n:
    raise ValueError("Message too large for key size!")

# ---------- Encryption ----------
cipher = pow(msg_num, e, n)
print("\nEncrypted Message:")
print(cipher)
print("-------------------------------------")

# ---------- Decryption ----------
plain_num = pow(cipher, d, n)

# Convert back
try:
    plain_text = number_to_text(plain_num)
    print("\nDecrypted Message:")
    print("-------------------------------------")
    print(plain_text)
except:
    print("\nDecrypted Numeric Message:")
    print(plain_num)
    print("-------------------------------------")
