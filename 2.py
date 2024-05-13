import binascii

def bxor(str1, str2):
    tmp =  bytes([x ^ y for (x, y) in zip(str1, str2)])
    return binascii.b2a_hex(tmp)

msg1 = "1c0111001f010100061a024b53535009181c"
msg2 = "686974207468652062756c6c277320657965"
msg1 = binascii.a2b_hex(msg1)
msg2 = binascii.a2b_hex(msg2)
ans = bxor(msg1, msg2)
print(ans)