from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
from Crypto import Random


def generate_AES_key():
    key_bytes = Random.get_random_bytes(32)
    return key_bytes

def encrypt_AES256(plaintext, key_bytes):
    plaintext_bytes = bytes(plaintext.encode('utf-8'))
    padded_plaintext_bytes = plaintext_bytes + b"\0" * (AES.block_size - len(plaintext_bytes) % AES.block_size)

    iv_bytes = Random.get_random_bytes(AES.block_size)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)

    ciphertext_bytes = cipher.encrypt(padded_plaintext_bytes)
    ciphertext = base64.b64encode(ciphertext_bytes).decode('utf-8')

    return ciphertext, iv_bytes

def remove_padding_from_base64_string(base64_string):
    padding_length = len(base64_string) % 4
    if padding_length > 0:
        base64_string += b"=" * (4 - padding_length)
    decoded_bytes = base64.b64decode(base64_string)
    stripped_bytes = decoded_bytes.rstrip(b"=")
    return stripped_bytes

def add_padding_to_base64_string(base64_string):
    missing_padding = len(base64_string) % 4
    if missing_padding != 0:
        base64_string += "=" * (4 - missing_padding)
    return base64_string.encode('utf-8')

def decrypt_AES256(ciphertext, key, iv):
    key_bytes = base64.decodebytes(remove_padding_from_base64_string(key))
    iv_bytes = base64.decodebytes(remove_padding_from_base64_string(iv))
    ciphertext_bytes = base64.decodebytes(remove_padding_from_base64_string(ciphertext))

    cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)

    plaintext_bytes = cipher.decrypt(ciphertext_bytes)
    plaintext = unpad(plaintext_bytes, AES.block_size)

    return plaintext.decode('utf-8')

action = input("1:加密，2:解密")
if action == "1":
    text = input("明文：")

    key = generate_AES_key()
    cip, iv = encrypt_AES256(text, key)
    print("Key:", base64.b64encode(key).decode('utf-8'))
    print("密文：", cip)
    print("IV：", base64.b64encode(iv).decode('utf-8'))
else:
    dec_text = input("输入密文：")
    dec_key = input("输入秘钥key（base64编码）：")
    dec_iv = input("输入IV（base64编码）：")
    key_dec = base64.b64decode(add_padding_to_base64_string(dec_key))
    iv_dec = base64.b64decode(add_padding_to_base64_string(dec_iv))
    plaintext = decrypt_AES256(dec_text.encode('utf-8'), key_dec, iv_dec)
    print("明文：", plaintext)