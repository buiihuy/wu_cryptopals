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