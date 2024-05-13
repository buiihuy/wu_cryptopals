from Cryptodome.Cipher import AES
import base64

def decode_aes_ecb(ciphertext):
    key = b'YELLOW SUBMARINE'
    decipher = AES.new(key, AES.MODE_ECB)
    plaintext = decipher.decrypt(ciphertext)
    return plaintext

if __name__ == '__main__':
    fp = open('7.txt', 'r')
    data = fp.read()
    data = data.strip()
    print(type(data))
    ciphertext = base64.b64decode(data)
    plaintext = decode_aes_ecb(ciphertext)
    print(plaintext)