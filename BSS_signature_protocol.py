import math
import random

# Signer's public and private keys based on the algorithm (RSA-based blind signature)
# Hardcoded as per the example on the whiteboard: N = 33, e = 7, d = 3
p = 11
q = 3
N = p * q  # 33
phi = (p - 1) * (q - 1)  # 20
e = 7
d = pow(e, -1, phi)  # Computes d = 3 (modular inverse of e modulo phi)

# Take input from user: the message M (should be an integer less than N for this demo)
M = int(input(f"Enter the message M (integer between 0 and {N-1}): "))

# User selects a random r such that 1 < r < N and gcd(r, N) = 1
while True:
    r = random.randint(2, N - 2)
    if math.gcd(r, N) == 1:
        break

# Step-by-step computation with formatted output
print("\n=== BSS (Blind RSA) Signature Protocol Simulation ===")
print(f"Signer's Public Key: (e = {e}, N = {N})")
print(f"Signer's Private Key: d = {d} (kept secret)")
print(f"User's Message: M = {M}")
print(f"User's Random Blinding Factor: r = {r}")

# User computes the blinded message: bm = (M * r^e) mod N
r_e = pow(r, e, N)
bm = (M * r_e) % N
print(f"\nStep 1: Blinded Message Computation")
print(f"   r^e mod N = {r}^ {e} mod {N} = {r_e}")
print(f"   bm = (M * r^e) mod N = ({M} * {r_e}) mod {N} = {bm}")

# Signer signs the blinded message: s' = bm^d mod N
s_prime = pow(bm, d, N)
print(f"\nStep 2: Signer Computes Blind Signature")
print(f"   s' = bm^d mod N = {bm}^ {d} mod {N} = {s_prime}")

# User unblinds the signature: s = (s' * r^{-1}) mod N
inv_r = pow(r, -1, N)
s = (s_prime * inv_r) % N
print(f"\nStep 3: User Unblinds the Signature")
print(f"   r^{-1} mod N = {inv_r}")
print(f"   s = (s' * r^{-1}) mod N = ({s_prime} * {inv_r}) mod {N} = {s}")

# Verification: Compute s^e mod N and check if it equals M
m_prime = pow(s, e, N)
print(f"\nStep 4: Signature Verification")
print(f"   m' = s^e mod N = {s}^ {e} mod {N} = {m_prime}")
if m_prime == M:
    print("   Verification Successful: m' == M")
else:
    print("   Verification Failed: m' != M")

print("=== End of Simulation ===")