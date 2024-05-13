import binascii

if __name__ == '__main__':
    plaintext = b'''Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal'''
    k = b'ICE'
    key = k * len(plaintext)
    key = key[:len(plaintext)]
    ciphertext = bytes([x ^ y for (x, y) in zip(plaintext, key)])
    print(binascii.b2a_hex(ciphertext))