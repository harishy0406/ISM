import math
import random

# Fixed parameters from the example (small for demo/educational purposes)
p = 11
q = 3
N = p * q          # 33
e = 7
phi = (p - 1) * (q - 1)  # 20
d = pow(e, -1, phi)      # 3

print("=== Blind RSA Signature (BSS) ===")
print(f"Public key:  e = {e}, N = {N}")
print(f"(Private key d = {d} is used by signer only)")
print("-" * 50)

# Get message from user (accepts both number and text)
user_input = input("Enter your message (number or any text): ").strip()

# Convert input to integer message M
try:
    if user_input.isdigit():
        M = int(user_input)
    else:
        # Simple way: convert text to number using hash (for demo)
        M = sum(ord(c) for c in user_input) % N
        print(f"Text message → converted to number: M = {M} (mod {N})")
except:
    print("Invalid input. Using default message M = 8")
    M = 8

if M >= N or M < 0:
    M = M % N
    print(f"Message adjusted: M = {M} (mod {N})")

print(f"\nOriginal message value: M = {M}")

# ------------------------------
# User side: Blinding
# ------------------------------
# Choose random r coprime with N
while True:
    r = random.randint(2, N-1)
    if math.gcd(r, N) == 1:
        break

# Blinded message: bm = M * r^e mod N
r_e = pow(r, e, N)
bm = (M * r_e) % N

# ------------------------------
# Signer side: Blind signing
# ------------------------------
s_prime = pow(bm, d, N)          # s' = bm^d mod N

# ------------------------------
# User side: Unblinding
# ------------------------------
r_inv = pow(r, -1, N)
s = (s_prime * r_inv) % N        # final signature s

# ------------------------------
# Verification
# ------------------------------
m_recovered = pow(s, e, N)       # s^e mod N should equal M

# ------------------------------
# Final formatted output
# ------------------------------
print("\n" + "=" * 50)
print("RESULTS:")
print("-" * 50)
print(f"Message (M)              : {M}")
print(f"Blinding factor (r)      : {r}")
print(f"Blinded message (bm)     : {bm}")
print(f"Blind signature (s')     : {s_prime}")
print(f"Final signature (s)      : {s}")
print("-" * 50)
print(f"Verification: s^e mod N  = {m_recovered}")
print(f"Original M               = {M}")

if m_recovered == M:
    print("\n✅ SIGNATURE IS VALID")
else:
    print("\n❌ SIGNATURE VERIFICATION FAILED")

print("=" * 50)