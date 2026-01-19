# Intelligent Cryptography Implementation

import random

# ---------- Helper Functions ----------

def to_number(msg):
    if msg.isdigit():
        return int(msg), "num"
    else:
        num = int.from_bytes(msg.encode('utf-8'), 'big')
        return num, "text"


def to_message(num, mode):
    if mode == "num":
        return str(num)
    else:
        length = (num.bit_length() + 7) // 8
        return num.to_bytes(length, 'big').decode('utf-8')


# ---------- Intelligent Encryption ----------

def smart_encrypt(original, secret):
    # Random intelligent split
    part_a = random.randint(1, original - 1)
    part_b = original - part_a

    # XOR-based encryption
    enc_a = part_a ^ secret
    enc_b = part_b ^ secret

    return enc_a, enc_b


# ---------- Intelligent Decryption ----------

def smart_decrypt(enc_a, enc_b, secret):
    part_a = enc_a ^ secret
    part_b = enc_b ^ secret

    recovered = part_a + part_b
    return recovered


# ---------- Main Execution ----------

if __name__ == "__main__":
    print("\n=== Intelligent Cryptography ===")
    user_input = input("Enter data (number / text / symbols): ")
    key_value = int(input("Enter secret key (number): "))

    data_num, data_type = to_number(user_input)

    print("\nOriginal Data (numeric form):", data_num)

    # Encryption
    c1, c2 = smart_encrypt(data_num, key_value)

    print("\n--- Encryption ---")
    print("Encrypted Part 1:", c1)
    print("Encrypted Part 2:", c2)

    # Decryption
    recovered_num = smart_decrypt(c1, c2, key_value)
    recovered_msg = to_message(recovered_num, data_type)

    print("\n--- Decryption ---")
    print("Recovered Numeric Data:", recovered_num)
    print("Recovered Original Message:", recovered_msg)
