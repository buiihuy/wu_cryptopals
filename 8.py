import binascii

def has_repeated_block(line, block_size = 16):
    if len(line) % block_size != 0:
        print('Error length')
        exit(0)
    else:
        num_block = len(line) // block_size
    blocks = [line[i * block_size : (i + 1) * block_size] for i in range(num_block)]
    if len(set(blocks)) != num_block:
        return True
    else:
        return False

if __name__ == '__main__':
    fp = open('8.txt', 'r')
    data = [binascii.a2b_hex(line.strip()) for line in fp]
    hits = [line for line in data if has_repeated_block(line)]
    print(hits)