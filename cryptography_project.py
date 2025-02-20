import numpy as np
import time
import base64
from itertools import cycle
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


# ----- PLAYFAIR CIPHER -----
def playfair_cipher(text, key, mode="encrypt"):
    def generate_playfair_matrix(key):
        key = key.upper().replace("J", "I")  # Replace 'J' with 'I'
        matrix, seen = [], set()
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        for char in key + alphabet:
            if char not in seen:
                seen.add(char)
                matrix.append(char)
        return [matrix[i:i+5] for i in range(0, 25, 5)]

    def format_text(text):
        text = text.upper().replace("J", "I").replace(" ", "")
        formatted_text, i = "", 0
        while i < len(text):
            a = text[i]
            b = text[i + 1] if i + 1 < len(text) else "X"
            if a == b:
                formatted_text += a + "X"
                i += 1
            else:
                formatted_text += a + b
                i += 2
        return formatted_text if len(formatted_text) % 2 == 0 else formatted_text + "X"

    def find_position(matrix, char):
        for row in range(5):
            for col in range(5):
                if matrix[row][col] == char:
                    return row, col

    matrix = generate_playfair_matrix(key)
    text = format_text(text) if mode == "encrypt" else text
    result, shift = "", 1 if mode == "encrypt" else -1

    for i in range(0, len(text), 2):
        a, b = text[i], text[i + 1]
        row_a, col_a = find_position(matrix, a)
        row_b, col_b = find_position(matrix, b)
        if row_a == row_b:
            result += matrix[row_a][(col_a + shift) % 5] + matrix[row_b][(col_b + shift) % 5]
        elif col_a == col_b:
            result += matrix[(row_a + shift) % 5][col_a] + matrix[(row_b + shift) % 5][col_b]
        else:
            result += matrix[row_a][col_b] + matrix[row_b][col_a]

    return result if mode == "encrypt" else result.replace("X", "")

# ----- RAIL FENCE CIPHER -----
def rail_fence_encrypt(plaintext, depth):
    fence = [[] for _ in range(depth)]
    rails = cycle(list(range(depth)) + list(range(depth-2, 0, -1)))
    for c in plaintext:
        fence[next(rails)].append(c)
    return ''.join(''.join(row) for row in fence)

def rail_fence_decrypt(ciphertext, depth):
    fence = [[] for _ in range(depth)]
    rails = cycle(list(range(depth)) + list(range(depth-2, 0, -1)))
    order = sorted(range(len(ciphertext)), key=lambda x: next(rails))
    for i, c in zip(order, ciphertext):
        fence[i % depth].append(c)
    return ''.join(''.join(row) for row in zip(*fence))

# ----- AES ENCRYPTION -----
def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return base64.b64encode(iv + ciphertext).decode()

def aes_decrypt(ciphertext, key):
    data = base64.b64decode(ciphertext)
    iv = data[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data[16:]), AES.block_size).decode()

# ----- RSA KEY EXCHANGE -----
def generate_rsa_keys():
    key = RSA.generate(2048)
    return key.export_key(), key.publickey().export_key()

def rsa_encrypt(message, public_key):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    return base64.b64encode(cipher.encrypt(message)).decode()

def rsa_decrypt(ciphertext, private_key):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(base64.b64decode(ciphertext)).decode()

# ----- MEASURE EXECUTION TIME -----
def measure_time(func, *args):
    start = time.time()
    result = func(*args)
    return result, time.time() - start

# ----- TESTING IMPLEMENTATION -----
if __name__ == "__main__":
    plaintext = "SECRETMESSAGE"
    playfair_key = "MYKEY"
    rail_fence_depth = 4

    # Playfair Cipher
    playfair_ciphertext, pf_enc_time = measure_time(playfair_cipher, plaintext, playfair_key, "encrypt")
    decrypted_playfair_text, pf_dec_time = measure_time(playfair_cipher, playfair_ciphertext, playfair_key, "decrypt")

    # Rail Fence Cipher
    rail_fence_ciphertext, rf_enc_time = measure_time(rail_fence_encrypt, playfair_ciphertext, rail_fence_depth)
    decrypted_rail_fence, rf_dec_time = measure_time(rail_fence_decrypt, rail_fence_ciphertext, rail_fence_depth)

    # AES + RSA
    rsa_private, rsa_public = generate_rsa_keys()
    secret_key = b'Sixteen byte key'
    encrypted_key, rsa_enc_time = measure_time(rsa_encrypt, secret_key, rsa_public)
    decrypted_key, rsa_dec_time = measure_time(rsa_decrypt, encrypted_key, rsa_private)

    aes_ciphertext, aes_enc_time = measure_time(aes_encrypt, plaintext, secret_key)
    decrypted_text, aes_dec_time = measure_time(aes_decrypt, aes_ciphertext, secret_key)

    # OUTPUT RESULTS WITH TIME MEASUREMENTS
    print(f"Playfair Ciphertext: {playfair_ciphertext} | Time: {pf_enc_time:.6f}s")
    print(f"Decrypted Playfair Text: {decrypted_playfair_text} | Time: {pf_dec_time:.6f}s")
    print(f"Rail Fence Ciphertext: {rail_fence_ciphertext} | Time: {rf_enc_time:.6f}s")
    print(f"Decrypted Rail Fence Text: {decrypted_rail_fence} | Time: {rf_dec_time:.6f}s")
    print(f"AES Ciphertext: {aes_ciphertext} | Time: {aes_enc_time:.6f}s")
    print(f"Decrypted AES Text: {decrypted_text} | Time: {aes_dec_time:.6f}s")
    print(f"RSA Encrypted Key: {encrypted_key[:30]}... | Time: {rsa_enc_time:.6f}s")
    print(f"RSA Decrypted Key: {decrypted_key} | Time: {rsa_dec_time:.6f}s")
