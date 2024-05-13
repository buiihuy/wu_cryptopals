from random import randint
from Cryptodome.Cipher import AES

character = list(range(65, 91)) + list(range(97, 123)) + [32]

def bxor(str1, str2):
    return bytes([x ^ y for (x, y) in zip(str1, str2)])

def calc_score(ciphertext):
    best = None
    for i in range(2 ** 8):
        ii = i.to_bytes(1, byteorder='big')
        key = ii * len(ciphertext)
        plaintext = bxor(key, ciphertext)
        score = sum(x in character for x in plaintext)
        if best == None or score > best['score']:
            best = {'plaintext': plaintext, 'score': score, 'key': key}
    return best

def pkcs7(message, block_size):
    padding_length = block_size - len(message) % block_size
    padding = bytes([padding_length]) * padding_length
    return message + padding

def generate_key(length: int = 16) -> bytes:
    return bytes([randint(0, 255) for _ in range(length)])

def is_valid_padding(msg):
    padding_length = msg[-1]
    l = len(msg)
    i = l - 1
    while(i >= l - padding_length):
        if msg[i] != padding_length:
            return False
        else:
            i -= 1
    return True

def unpad(msg):
    if is_valid_padding(msg):
        padding_length = msg[-1]
        message_length = len(msg) - padding_length
        return msg[:message_length]
    else:
        print('INVALID PADDING')
        exit(0)

# encrypt 1 block
def AES_encrypt(plaintext, key):
    encryptor = AES.new(key, AES.MODE_ECB)
    return encryptor.encrypt(plaintext)

# decrypt 1 block
def AES_decrypt(ciphertext, key):
    decryptor = AES.new(key, AES.MODE_ECB)
    return decryptor.decrypt(ciphertext)

def AES_encrypt_ecb(plaintext, key):
    plaintext = pkcs7(plaintext, 16)
    nb = len(plaintext) // 16
    blocks = [plaintext[i * 16 : (i + 1) * 16] for i in range(nb)]
    return b''.join(AES_encrypt(block, key) for block in blocks)