import cryptopals
from Cryptodome.Cipher import AES

strings = [
    'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
    'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
    'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
    'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
    'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
    'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
    'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
    'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
    'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
    'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93'
]
random_key = cryptopals.generate_key()

def AES_encrypt_cbc(plaintext):
    iv = cryptopals.generate_key()
    encryptor = AES.new(random_key, AES.MODE_CBC, iv)
    plaintext = cryptopals.pkcs7(plaintext, 16)
    ciphertext = encryptor.encrypt(plaintext)
    return iv, ciphertext

def AES_decrypt_cbc(ciphertext, iv):
    decryptor = AES.new(random_key, AES.MODE_CBC, iv)
    plaintext = decryptor.decrypt(ciphertext)
    return plaintext

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

if __name__ == '__main__':
    for s in strings:
        ret = b''
        msg = bytes(s, 'utf-8')
        iv, ciphertext = AES_encrypt_cbc(msg)
        num_block = len(ciphertext) // 16
        blocks = [ciphertext[i * 16 : (i + 1) * 16] for i in range(num_block)]
        for block in blocks:
            res = b''
            for k in range(15, -1, -1):
                len_padding = 16 - k
                padding = bytes([len_padding]) * len_padding
                real_data = iv[k:]
                for j in range(256):
                    candidate = bytes([j]) + res
                    fake_data = cryptopals.bxor(cryptopals.bxor(real_data, candidate), padding)
                    iv = iv[:k] + fake_data
                    tmp = AES_decrypt_cbc(block, iv)
                    if is_valid_padding(tmp):
                        res = candidate
                        break
                    else:
                        continue
            iv = block
            ret += res
        print(res)