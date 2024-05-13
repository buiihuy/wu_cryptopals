import cryptopals
import binascii

fp = open('25.txt', 'r')
plaintext = bytes(fp.read(), 'ascii')
fp.close()

random_key = cryptopals.generate_key()
nonce = cryptopals.generate_key()

def AES_decrypt_encrypt_ctr(key, text, iv = b'\x00' * 8, nonce = 0):
    ret = b''
    for i in range(0, len(text), 16):
        block = text[i : i + 16]
        real_iv = (binascii.a2b_hex(f'{nonce:016x}') + iv)[::-1]
        ret += cryptopals.bxor(block, cryptopals.AES_encrypt(real_iv, key))
        nonce += 1
    return ret

def edit(offset, newtext):
    fake_plaintext = plaintext[:offset] + newtext + plaintext[offset + len(newtext) :]
    fake_ciphertext = AES_decrypt_encrypt_ctr(random_key, fake_plaintext)
    return fake_ciphertext

if __name__ == '__main__':
    real_ciphertext = edit(0, b'')
    l = len(real_ciphertext)
    keystream = edit(0, b'\x00' * l)
    real_plaintext = cryptopals.bxor(real_ciphertext, keystream)
    print(real_plaintext == plaintext)    