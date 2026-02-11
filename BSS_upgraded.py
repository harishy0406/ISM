import math
import random
import hashlib
from typing import Tuple

print("=== Blind RSA Signature (BSS) ===")
def is_prime(n: int) -> bool:
    """Miller-Rabin primality test (probabilistic but very accurate for our needs)."""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False

    # Write n as 2^r * d + 1
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Witnesses for numbers < 2^64 (very reliable)
    witnesses = [2, 3, 5, 7, 11, 13, 17, 23, 29, 31, 37]
    if n < 2047:
        witnesses = [2]
    elif n < 1373653:
        witnesses = [2, 3]
    elif n < 25326001:
        witnesses = [2, 3, 5]

    for a in witnesses:
        if a >= n:
            break
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


def generate_random_prime(bits: int) -> int:
    """Generate a random prime with approximately `bits` bits."""
    while True:
        # Generate odd random number in range [2^(bits-1) + 1, 2^bits - 1]
        p = random.randrange(1 << (bits - 1), 1 << bits)
        if p % 2 == 0:
            p += 1
        if is_prime(p):
            return p


def generate_rsa_keys(modulus_bits: int = 512) -> Tuple[Tuple[int, int], int, int, int]:
    """
    Generate RSA key pair with ~512-bit modulus.
    Returns: (public_key: (e, N)), private_key: d, p, q
    """
    print("Generating two ~256-bit primes... (this may take a few seconds)")
    
    half_bits = modulus_bits // 2
    p = generate_random_prime(half_bits)
    q = generate_random_prime(half_bits)
    
    # Ensure they are different and not too close
    while p == q or abs(p - q) < (1 << (half_bits - 16)):
        q = generate_random_prime(half_bits)

    N = p * q
    phi = (p - 1) * (q - 1)

    # Choose common public exponent
    e = 65537
    if math.gcd(e, phi) != 1:
        # fallback (very rare)
        e = 17
        while math.gcd(e, phi) != 1:
            e += 2

    d = pow(e, -1, phi)

    print(f"  p ≈ 2^{p.bit_length()}-bit")
    print(f"  q ≈ 2^{q.bit_length()}-bit")
    print(f"  N  = {N.bit_length()}-bit modulus")

    return (e, N), d, p, q


def message_to_int(message: str, N: int) -> int:
    """Convert any message (text or number string) to integer < N using SHA-256."""
    if message.isdigit():
        try:
            m = int(message)
            return m % N
        except:
            pass

    # Hash the message
    h = hashlib.sha256(message.encode()).digest()
    m = int.from_bytes(h, "big")
    return m % N


def blind_signature_protocol(message: str, modulus_bits: int = 512):
    """Run the complete Blind RSA signature protocol."""
    print("\n=== Blind RSA Signature – 512-bit keys ===\n")

    # 1. Generate keys
    (e, N), d, p, q = generate_rsa_keys(modulus_bits)

    # 2. Prepare message
    M = message_to_int(message, N)
    print(f"\nMessage: {message!r}")
    print(f"M (integer mod N): {M}")

    # 3. Blinding (User)
    while True:
        r = random.randrange(1, N)
        if math.gcd(r, N) == 1:
            break

    blinded = (M * pow(r, e, N)) % N
    print(f"Blinding factor r:   {r}")
    print(f"Blinded message:     {blinded}")

    # 4. Blind signing (Signer)
    blind_sig = pow(blinded, d, N)
    print(f"Blind signature s':  {blind_sig}")

    # 5. Unblinding (User)
    r_inv = pow(r, -1, N)
    signature = (blind_sig * r_inv) % N
    print(f"Final signature s:   {signature}")

    # 6. Verification
    recovered = pow(signature, e, N)
    print(f"\nVerification:")
    print(f"  s^e mod N  = {recovered}")
    print(f"  Original M = {M}")

    valid = (recovered == M)
    print("  → VALID" if valid else "  → INVALID")

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("-" * 70)
    print(f"Message:          {message}")
    print(f"M:                {M}")
    print(f"N bit length:     {N.bit_length()}")
    print(f"Public key (e,N): ({e}, {N})")
    print(f"Signature:        {signature}")
    print(f"Valid:            {'YES' if valid else 'NO'}")
    print("=" * 70)


def main():
    message = input("Enter message (text or number): ").strip()
    if not message:
        message = "This is a test message for blind signature"

    blind_signature_protocol(message, modulus_bits=512)


if __name__ == "__main__":
    main()