def gcd(a, b):
    while a != b:
        if a > b:
            a = a - b
        else:
            b = b - a
    return a

def ext_euclid_algo(a, b):
    m, n = a, b
    xm, ym = 1, 0
    xn, yn = 0, 1
    while (n != 0):
        q = m // n
        r = m % n
        xr, yr = xm - q * xn, ym - q * yn
        m = n
        xm, ym = xn, yn
        n = r
        xn, yn = xr, yr
    return (xm, ym)

if __name__ == '__main__':
    a = int(input('a = '))
    b = int(input('b = '))
    print(ext_euclid_algo(a, b))
