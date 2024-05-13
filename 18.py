import cryptopals
import base64
import binascii

def AES_decrypt_ctr(key, cipher, iv = b'\x00' * 8, nonce = 0):
    ret = b''
    for i in range(0, len(cipher), 16):
        block = cipher[i : i + 16]
        real_iv = (binascii.a2b_hex(f'{nonce:016x}') + iv)[::-1]
        ret += cryptopals.bxor(block, cryptopals.AES_encrypt(real_iv, key))
        nonce += 1
    return ret

if __name__ == '__main__':
    ciphertext = 'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='
    key = b'YELLOW SUBMARINE'
    ret = AES_decrypt_ctr(key, base64.b64decode(ciphertext))
    print(ret)