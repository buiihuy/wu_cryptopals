from random import randint
import os

def pkcs7(message, block_size):
    padding_length = block_size - len(message) % block_size
    padding = bytes([padding_length]) * padding_length
    return message + padding

if __name__ == '__main__':
    length = randint(20, 70)
    print("length = ", length)
    block_size = randint(10, 30)
    print("block_size = ", block_size)
    msg = os.urandom(length)
    print("msg = ", msg)
    print(pkcs7(msg, block_size))