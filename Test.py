import os
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from PIL import Image

# ============================================================
# ---------------------   RSA FUNCTIONS   ---------------------
# ============================================================

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    open("private.pem", "wb").write(private_key)
    open("public.pem", "wb").write(public_key)

    print("\n[✓] RSA Key Pair Generated!")
    print("private.pem & public.pem created.\n")


def rsa_encrypt(data, public_key_path="public.pem"):
    if not os.path.exists(public_key_path):
        print(f"[!] Public key '{public_key_path}' not found — generating new RSA keypair.")
        generate_rsa_keys()

    with open(public_key_path, "rb") as f:
        key_data = f.read()
    key = RSA.import_key(key_data)
    cipher_rsa = PKCS1_OAEP.new(key)
    encrypted = cipher_rsa.encrypt(data)
    return encrypted


def rsa_decrypt(cipher, private_key_path="private.pem"):
    if not os.path.exists(private_key_path):
        raise FileNotFoundError(f"Private key '{private_key_path}' not found. Generate keys (menu option 1) before decrypting.")
    with open(private_key_path, "rb") as f:
        key_data = f.read()
    key = RSA.import_key(key_data)
    cipher_rsa = PKCS1_OAEP.new(key)
    decrypted = cipher_rsa.decrypt(cipher)
    return decrypted


# ============================================================
# --------------------   SIMPLIFIED DES   --------------------
# ============================================================
# Educational S-DES implementation (classic 8-bit block, 10-bit key)
# Not secure — for learning and demonstration only.

# Permutation helpers (operate on lists of bits)

def permute(bits, table):
    return [bits[i - 1] for i in table]


def left_shift(bits, n):
    return bits[n:] + bits[:n]

# Key schedule P10 and P8
P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
P8  = [6, 3, 7, 4, 8, 5, 10, 9]

# Initial and inverse permutations
IP  = [2, 6, 3, 1, 4, 8, 5, 7]
IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]

# Expansion/permutation and P4
EP = [4, 1, 2, 3, 2, 3, 4, 1]
P4 = [2, 4, 3, 1]

# S-boxes (as tables)
S0 = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 3, 2]
]

S1 = [
    [0, 1, 2, 3],
    [2, 0, 1, 3],
    [3, 0, 1, 0],
    [2, 1, 0, 3]
]


def bits_from_int(value, length):
    return [(value >> (length - 1 - i)) & 1 for i in range(length)]


def int_from_bits(bits):
    val = 0
    for b in bits:
        val = (val << 1) | b
    return val


def generate_sdes_subkeys(key10):
    # key10: integer 0..1023 (10 bits)
    bits = bits_from_int(key10, 10)
    permuted = permute(bits, P10)
    left = permuted[:5]
    right = permuted[5:]

    # first subkey
    left1 = left_shift(left, 1)
    right1 = left_shift(right, 1)
    combined1 = left1 + right1
    K1 = int_from_bits(permute(combined1, P8))

    # second subkey
    left2 = left_shift(left1, 2)
    right2 = left_shift(right1, 2)
    combined2 = left2 + right2
    K2 = int_from_bits(permute(combined2, P8))

    return K1, K2


def fk(bits8, subkey):
    # bits8: list of 8 bits
    left = bits8[:4]
    right = bits8[4:]

    # expand and xor with subkey
    expanded = permute(right, EP)
    sk_bits = bits_from_int(subkey, 8)
    xor_res = [a ^ b for a, b in zip(expanded, sk_bits)]

    # S-box lookups
    left_xor = xor_res[:4]
    right_xor = xor_res[4:]

    # S0
    row = (left_xor[0] << 1) | left_xor[3]
    col = (left_xor[1] << 1) | left_xor[2]
    s0_val = S0[row][col]
    s0_bits = bits_from_int(s0_val, 2)

    # S1
    row = (right_xor[0] << 1) | right_xor[3]
    col = (right_xor[1] << 1) | right_xor[2]
    s1_val = S1[row][col]
    s1_bits = bits_from_int(s1_val, 2)

    # combine and P4
    combined = s0_bits + s1_bits
    p4_res = permute(combined, P4)

    # xor with left
    left_res = [l ^ p for l, p in zip(left, p4_res)]

    return left_res + right


def sdes_encrypt_byte(b, key10):
    # returns encrypted byte (0..255)
    bits = bits_from_int(b, 8)
    K1, K2 = generate_sdes_subkeys(key10)

    # initial permutation
    ip = permute(bits, IP)

    # fk with K1
    stage1 = fk(ip, K1)

    # switch left and right
    sw = stage1[4:] + stage1[:4]

    # fk with K2
    stage2 = fk(sw, K2)

    # inverse IP
    cipher_bits = permute(stage2, IP_INV)
    return int_from_bits(cipher_bits)


def sdes_decrypt_byte(b, key10):
    bits = bits_from_int(b, 8)
    K1, K2 = generate_sdes_subkeys(key10)

    ip = permute(bits, IP)
    # note: decryption uses K2 then K1
    stage1 = fk(ip, K2)
    sw = stage1[4:] + stage1[:4]
    stage2 = fk(sw, K1)
    plain_bits = permute(stage2, IP_INV)
    return int_from_bits(plain_bits)


def sdes_encrypt(data_bytes, key10):
    # data_bytes: bytes-like, returns bytes of same length
    res = bytearray()
    for b in data_bytes:
        res.append(sdes_encrypt_byte(b, key10))
    return bytes(res)


def sdes_decrypt(data_bytes, key10):
    res = bytearray()
    for b in data_bytes:
        res.append(sdes_decrypt_byte(b, key10))
    return bytes(res)


def generate_sdes_key():
    # generate a random 10-bit integer (0..1023) and return as int
    raw = get_random_bytes(2)
    val = int.from_bytes(raw, "big") & 0x3FF  # mask to 10 bits
    return val


# ============================================================
# ------------------   IMAGE STEGANOGRAPHY   -----------------
# ============================================================

def hide_data_in_image(input_path, data, output_path="encoded.png"):
    if isinstance(data, str):
        data = data.encode()

    img = Image.open(input_path).convert("RGBA")
    pixels = img.load()

    data_len = len(data)
    header = data_len.to_bytes(4, byteorder="big")
    full = header + data
    bits = ''.join(f'{b:08b}' for b in full)

    capacity = img.width * img.height * 3
    if len(bits) > capacity:
        raise ValueError(f"Data too large to hide: need {len(bits)} bits, capacity is {capacity} bits")

    idx = 0
    total_bits = len(bits)

    for y in range(img.height):
        for x in range(img.width):
            px = pixels[x, y]
            if len(px) >= 4:
                r, g, b, a = px[0], px[1], px[2], px[3]
            elif len(px) == 3:
                r, g, b = px
                a = 255
            else:
                r, g, b, a = img.getpixel((x, y))[:4]

            if idx < total_bits:
                r = (r & ~1) | int(bits[idx]); idx += 1
            if idx < total_bits:
                g = (g & ~1) | int(bits[idx]); idx += 1
            if idx < total_bits:
                b = (b & ~1) | int(bits[idx]); idx += 1

            pixels[x, y] = (r, g, b, a)

            if idx >= total_bits:
                break
        if idx >= total_bits:
            break

    img.save(output_path, "PNG")
    print(f"[✓] Data hidden in image → {output_path} (stored {data_len} bytes)")
    return output_path


def extract_data_from_image(input_path):
    img = Image.open(input_path).convert("RGBA")
    pixels = img.load()

    bits = []
    for y in range(img.height):
        for x in range(img.width):
            r, g, b, a = pixels[x, y]
            bits.append(str(r & 1))
            bits.append(str(g & 1))
            bits.append(str(b & 1))

    bits_str = ''.join(bits)

    if len(bits_str) < 32:
        raise ValueError("Image doesn't contain embedded length header.")

    len_bits = bits_str[:32]
    data_len = int(len_bits, 2)
    total_data_bits = 32 + data_len * 8

    if len(bits_str) < total_data_bits:
        raise ValueError(f"Image does not contain the expected {data_len} bytes (need {total_data_bits} bits).")

    data_bits = bits_str[32: total_data_bits]
    data_bytes = int(data_bits, 2).to_bytes(data_len, byteorder="big")
    return data_bytes


# ============================================================
# ---------------------------  HYBRID  ------------------------
# ============================================================

def hybrid_encrypt(plaintext_bytes):
    # generate S-DES key (10-bit int)
    sdes_key = generate_sdes_key()
    ciphertext = sdes_encrypt(plaintext_bytes, sdes_key)
    # encrypt the 10-bit key with RSA (store as 2 bytes)
    enc_key = rsa_encrypt(sdes_key.to_bytes(2, "big"))
    return enc_key, ciphertext


def hybrid_decrypt(enc_key_blob, ciphertext_bytes):
    sdes_key_bytes = rsa_decrypt(enc_key_blob)
    if len(sdes_key_bytes) < 2:
        raise ValueError("Decrypted S-DES key blob is too short")
    sdes_key = int.from_bytes(sdes_key_bytes[:2], "big") & 0x3FF
    return sdes_decrypt(ciphertext_bytes, sdes_key)


# ============================================================
# ---------------------------  MENU  -------------------------
# ============================================================

def menu():
    while True:
        print("\n" + "="*60)
        print(" STEGOSAURUS – simplified DES (S-DES) + Steganography Tool")
        print("="*60)
        print("""
1. Generate RSA Key Pair
2. S-DES Encrypt Text (sdes.key, sdes.enc)
3. S-DES Decrypt Text
4. RSA Encrypt Text
5. RSA Decrypt Text
6. Hide Data in Image
7. Extract Data From Image
8. Hybrid S-DES + RSA Encrypt
9. Hybrid S-DES + RSA Decrypt
0. Exit
""")

        choice = input("Choose option: ")

        if choice == "1":
            generate_rsa_keys()

        elif choice == "2":
            text = input("Enter text: ").encode()
            key10 = generate_sdes_key()
            ct = sdes_encrypt(text, key10)
            open("sdes.key", "wb").write(key10.to_bytes(2, "big"))
            open("sdes.enc", "wb").write(ct)
            print("\n[✓] S-DES Encrypted → sdes.enc, sdes.key")

        elif choice == "3":
            key_bytes = open("sdes.key", "rb").read()
            key10 = int.from_bytes(key_bytes[:2], "big") & 0x3FF
            ct = open("sdes.enc", "rb").read()
            pt = sdes_decrypt(ct, key10)
            print("\nDecrypted Text:", pt.decode(errors="ignore"))

        elif choice == "4":
            text = input("Enter text: ").encode()
            ct = rsa_encrypt(text)
            open("rsa.enc", "wb").write(ct)
            print("\n[✓] RSA Encrypted → rsa.enc")

        elif choice == "5":
            ct = open("rsa.enc", "rb").read()
            pt = rsa_decrypt(ct)
            print("\nDecrypted Text:", pt.decode())

        elif choice == "6":
            img = input("Input image path: ")
            data = input("Enter data to hide: ").encode()
            hide_data_in_image(img, data)

        elif choice == "7":
            img = input("Input encoded image path: ")
            data = extract_data_from_image(img)
            # save extracted bytes to file for safe handling
            open("extracted_payload.bin", "wb").write(data)
            print("\nExtracted data written to extracted_payload.bin")

        elif choice == "8":
            text = input("Text to encrypt: ").encode()
            enc_key, cipher = hybrid_encrypt(text)
            open("hybrid.key", "wb").write(enc_key)
            open("hybrid.enc", "wb").write(cipher)
            print("\n[✓] Hybrid Encrypted → hybrid.enc, hybrid.key")

        elif choice == "9":
            enc_key = open("hybrid.key", "rb").read()
            cipher = open("hybrid.enc", "rb").read()
            pt = hybrid_decrypt(enc_key, cipher)
            print("\nDecrypted Text:", pt.decode(errors="ignore"))

        elif choice == "0":
            print("Exiting...")
            break

        else:
            print("Invalid choice!")


if __name__ == "__main__":
    menu()
