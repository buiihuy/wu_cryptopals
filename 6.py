import cryptopals
import base64

with open('6.txt', 'r') as fp:
    ciphertext = base64.b64decode(fp.read())
    fp.close()

def hamming_distance(s1, s2):
    return sum(bin(byte).count('1') for byte in cryptopals.bxor(s1, s2))

def break_repeated_xor(cipher: bytes, min_keysize=2, max_keysize=40):
    min_distance, current_min_keysize = None, None
    for keysize in range(min_keysize, max_keysize + 1):
        nb = min(len(cipher) // keysize, 4)
        blocks = []
        for i in range(nb):
            blocks.append(cipher[i * keysize : (i + 1) * keysize])
        distance = 0
        for i in range(nb):
            for j in range(i, nb):
                distance += hamming_distance(blocks[i], blocks[j])
        distance /= (keysize * nb * (nb - 1) / 2)
        if min_distance is None or min_distance > distance:
            min_distance, current_min_keysize = distance, keysize
    return current_min_keysize

def find_key_xor(ciphertext):
    keysize = break_repeated_xor(ciphertext)
    key = bytes()
    message_parts = list()
    for i in range(keysize):
        part = cryptopals.calc_score(bytes(ciphertext[i::keysize]))
        key += part['key']
        message_parts.append(part['plaintext'])
    message = bytes()
    for i in range(max(map(len, message_parts))):
        message += bytes([part[i] for part in message_parts if len(part)>=i+1])
    return {'plaintext':message, 'key':key}

if __name__ == '__main__':
    result = find_key_xor(ciphertext)
    print('key: ',result['key'],'\n')
    print('message:\n')
    print(result['plaintext'].decode())