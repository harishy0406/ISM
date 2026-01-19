# Hybrid Cryptography (Intelligent cryptography + Linear PKC)


# ASHIC :Adaptive Split-Hybrid Intelligent Cryptography

import random
import secrets
import hashlib

# =====================================================
# SECTION 1: DATA TRANSFORMATION
# =====================================================

def encode_data(msg):
    if msg.isdigit():
        return int(msg), "NUM"
    else:
        return int.from_bytes(msg.encode("utf-8"), "big"), "TXT"


def decode_data(num, mode):
    if mode == "NUM":
        return str(num)
    length = (num.bit_length() + 7) // 8
    return num.to_bytes(length, "big").decode("utf-8")


# =====================================================
# SECTION 2: INTELLIGENT SPLIT ENCRYPTION (NOVEL CORE)
# =====================================================

def adaptive_split_encrypt(value, sym_key):
    seed = secrets.randbits(32)
    random.seed(seed)

    x = random.randint(1, value - 1)
    y = value - x

    c1 = x ^ sym_key
    c2 = y ^ (sym_key >> 1)

    return c1, c2, seed


def adaptive_split_decrypt(c1, c2, sym_key):
    x = c1 ^ sym_key
    y = c2 ^ (sym_key >> 1)
    return x + y


# =====================================================
# SECTION 3: LINEAR PKC (KEY PROTECTION LAYER)
# =====================================================

def is_prime(n, k=8):
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
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_prime(bits):
    while True:
        p = secrets.randbits(bits)
        p |= (1 << bits - 1) | 1
        if is_prime(p):
            return p


def generate_keys(bits):
    p = gen_prime(bits)
    q = gen_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = pow(e, -1, phi)
    return (e, n), (d, n)


# =====================================================
# SECTION 4: ASHIC – FUSION ALGORITHM
# =====================================================

def ashic_encrypt(message, pub_key):
    data_num, mode = encode_data(message)

    session_key = secrets.randbits(64)

    c1, c2, seed = adaptive_split_encrypt(data_num, session_key)

    enc_session_key = pow(session_key, pub_key[0], pub_key[1])

    digest = hashlib.sha256(
        (str(c1) + str(c2) + str(seed)).encode()
    ).hexdigest()

    return {
        "C1": c1,
        "C2": c2,
        "SEED": seed,
        "ENC_KEY": enc_session_key,
        "HASH": digest,
        "MODE": mode
    }


def ashic_decrypt(packet, priv_key):
    session_key = pow(packet["ENC_KEY"], priv_key[0], priv_key[1])

    check_hash = hashlib.sha256(
        (str(packet["C1"]) + str(packet["C2"]) + str(packet["SEED"])).encode()
    ).hexdigest()

    if check_hash != packet["HASH"]:
        raise ValueError("Integrity violation detected")

    recovered_num = adaptive_split_decrypt(
        packet["C1"], packet["C2"], session_key
    )

    return decode_data(recovered_num, packet["MODE"])


# =====================================================
# SECTION 5: EXECUTION
# =====================================================

if __name__ == "__main__":

    print("\n=== ASHIC : Adaptive Split-Hybrid Intelligent Cryptography ===\n")

    bits = int(input("Enter PKC key size (256 / 512): "))
    public_key, private_key = generate_keys(bits)

    user_msg = input("Enter message (text / number / symbols): ")

    encrypted_packet = ashic_encrypt(user_msg, public_key)

    print("\n--- Cipher Output ---")
    for k, v in encrypted_packet.items():
        print(k, ":", v)

    print("\n--- Decryption ---")
    decrypted_msg = ashic_decrypt(encrypted_packet, private_key)
    print("Recovered Message:", decrypted_msg)
# =====================================================