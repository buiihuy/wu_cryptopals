import binascii

character = list(range(65, 91)) + list(range(97, 123)) + [32]

def calc_score(data):
    best = {'score': 0, 'key': 0}
    for i in range(2 ** 8):
        score = 0
        for c in data:
            tmp = c ^ i
            if tmp in character:
                score += 1
        if best['score'] == 0 or score > best['score']:
            best['score'] = score
            best['key'] = i
    return best

if __name__ == '__main__':
    super_score = 0
    best_data = ''
    key_to_encrypt = 0
    plaintext = ''
    fp = open('4.txt', 'r')
    while True:
        data = fp.readline()
        if data == '':
            break
        data = data.strip()
        data = binascii.a2b_hex(data)
        l = len(data)
        best = calc_score(data)
        if super_score == 0 or best['score'] > super_score:
            super_score = best['score']
            key_to_encrypt = best['key']
            best_data = data
    for c in best_data:
        plaintext += chr(c ^ key_to_encrypt)
    print(plaintext)