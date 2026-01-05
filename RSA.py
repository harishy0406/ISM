import math
# 1. Take two prime numbers as input
p = int(input("Enter first prime number (p): "))
q = int(input("Enter second prime number (q): "))

# 2. Calculate common modulus
n = p * q

# 3. Compute Euler's Totient Function
phi = (p - 1) * (q - 1)

# 4. Select public key e
e = int(input("Enter public key (e): "))
while e <= 1 or e >= phi or math.gcd(e, phi) != 1:
    print("Invalid e. It must be >1, <phi, and gcd(e, phi)=1")
    e = int(input("Enter public key (e) again: "))

# 5. Compute private key d
d = pow(e, -1, phi)

# Display keys
print("\nPublic Key (e, n):", (e, n))
print("Private Key (d, n):", (d, n))

# Message input
msg = int(input("\nEnter message (number): "))

# Encryption
c = pow(msg, e, n)
print("Encrypted message:", c)

# Decryption
m = pow(c, d, n)
print("Decrypted message:", m)