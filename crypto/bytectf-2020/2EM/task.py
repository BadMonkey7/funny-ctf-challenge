import random
from secret import flag
from Crypto.Util.number import bytes_to_long
pbox1 = [22, 28, 2, 21, 3, 26, 6, 14, 7, 16, 15, 9, 17, 19, 8, 11, 10, 1, 13, 31, 23, 12, 0, 27, 4, 18, 30, 29, 24, 20, 5, 25]
pbox2 = [17, 6, 7, 27, 4, 20, 11, 22, 2, 19, 9, 24, 23, 31, 15, 10, 18, 28, 5, 0, 16, 29, 25, 8, 3, 21, 30, 12, 14, 13, 1, 26]
def p(data,pbox):
    tmp = bin(data)[2:].rjust(32,'0')
    out = [ tmp[x] for x in pbox ]
    return int(''.join(out),2)

def genkey(l):
    return random.getrandbits(l)

def encrypt(key,msg):
    tmp1 = p(msg^key,pbox1)
    tmp2 = p(tmp1^key,pbox2)
    return tmp2^key

key = genkey(32)
flag = flag.ljust(44,'\x00')
for i in range(len(flag)/4):
    pt = bytes_to_long(flag[i*4:i*4+4])
    print encrypt(key,pt)
for i in range(2**22):
    pt = random.getrandbits(32)
    ct = encrypt(key,pt)
    print pt,ct


