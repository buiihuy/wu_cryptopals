import binascii
import cryptopals

def find_key(ciphertext):
    best = None
    for i in range(2 ** 8):
        ii = i.to_bytes(1, byteorder='big')
        key = ii * len(ciphertext)
        plaintext = cryptopals.bxor(key, ciphertext)
        score = sum(x in character for x in plaintext)
        if best == None or score > best['score']:
            best = {'plaintext': plaintext, 'score': score, 'key': key}
    return best

character = list(range(65, 91)) + list(range(97, 123)) + [32]
ciphertext = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
ciphertext = binascii.a2b_hex(ciphertext)
plaintext = find_key(ciphertext)
print(plaintext)