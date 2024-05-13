import base64
import string
import cryptopals
from random import randint
from Cryptodome.Cipher import AES

unknown_string = base64.b64decode(b'''Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK''')
random_key = cryptopals.generate_key()

def AES_encrypt_ecb(my_string):
    plaintext = my_string + unknown_string
    plaintext = cryptopals.pkcs7(plaintext, 16)
    cryptor = AES.new(random_key, AES.MODE_ECB)
    ciphertext = cryptor.encrypt(plaintext)
    return ciphertext

def guess_block_size():
    block_size = 1
    old_string = b'a' * block_size
    old_ciphertext = AES_encrypt_ecb(old_string)
    while True:
        block_size += 1
        new_string = b'a' * block_size
        new_ciphertext = AES_encrypt_ecb(new_string)
        if new_ciphertext[: block_size - 1] == old_ciphertext[: block_size - 1]:
            break
        else:
            old_ciphertext = new_ciphertext
    return block_size - 1

def detect_ecb_mode(block_size):
    my_string = b'a' * (2 * block_size)
    ciphertext = AES_encrypt_ecb(my_string)
    if ciphertext[0 : block_size] == ciphertext[block_size : block_size * 2]:
        return True
    else:
        return False
    
def crack():
    printable = string.printable

    len_target_bytes = 144
    target_bytes = ''

    for i in range(len_target_bytes):
        attacker_controlled = b'a' * (len_target_bytes - i - 1)
        ciphertext = AES_encrypt_ecb(attacker_controlled)

        for c in printable:
            brute_force_attacker_controlled = attacker_controlled + bytes(target_bytes, 'ascii') + bytes(c, 'ascii')
            brute_force_ciphertext = AES_encrypt_ecb(brute_force_attacker_controlled)
            if brute_force_ciphertext[128:144] == ciphertext[128:144]:
                target_bytes += c
                break
    return target_bytes

if __name__ == '__main__':
    block_size = guess_block_size()
    if detect_ecb_mode(block_size):
        res = crack()
        print(res)
    else:
        exit(0)