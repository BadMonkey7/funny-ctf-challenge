#!/usr/bin/env python3
import os
import random
import string
from hashlib import sha256

from Toy_AE import Toy_AE
from secret import FLAG

def proof_of_work():
    random.seed(os.urandom(8))
    proof = b''.join([random.choice(string.ascii_letters + string.digits).encode() for _ in range(20)])
    digest = sha256(proof).hexdigest().encode()
    print("sha256(XXXX+%s) == %s" % (proof[4:],digest))
    print("Give me XXXX:")
    x = input().encode()
    return False if len(x) != 4 or sha256(x + proof[4:]).hexdigest().encode() != digest else True

def pack(uid, uname, token, cmd, appendix):
    r = b''
    r += b'Uid=%d\xff' % uid
    r += b'UserName=%s\xff' % uname
    r += b'T=%s\xff' % token
    r += b'Cmd=%s\xff' % cmd
    r += appendix
    return r

def unpack(r):
    data = r.split(b"\xff")
    uid, uname, token, cmd, appendix = int(data[0][4:]), data[1][9:], data[2][2:], data[3][4:], data[4]
    return (uid, uname, token, cmd, appendix)

def apply_ticket():
    uid = int(input("Set up your user id:")[:5])
    uname = input("Your username:").encode("ascii")[:16]
    if uname == b"Administrator":
        print("Sorry, preserved username.")
        return
    token = sha256(uname).hexdigest()[:max(8, uid % 16)].encode("ascii")
    cmd = input("Your command:").encode("ascii")[:16]
    if cmd == b"Give_Me_Flag":
        print("Not allowed!")
        return
    appendix = input("Any Appendix?").encode("ascii")[:16]
    msg = pack(uid, uname, token, cmd, appendix)
    ct, te = ae.encrypt(msg)
    print("Your ticket:%s" % ct.hex())
    print("With my Auth:%s" % te.hex())

def check_ticket():
    ct = bytes.fromhex(input("Ticket:"))
    te = bytes.fromhex(input("Auth:"))
    msg = ae.decrypt(ct, te)
    assert msg
    uid, uname, token, cmd, appendix = unpack(msg)
    if uname == b"Administrator" and cmd == b"Give_Me_Flag":
        print(FLAG)
        exit(0)
    else:
        print("Nothing happend.")

def menu():
    print("Menu:")
    print("[1] Apply Ticket")
    print("[2] Check Ticket")
    print("[3] Exit")
    op = int(input("Your option:"))
    assert op in range(1, 4)
    if op == 1:
        apply_ticket()
    elif op == 2:
        check_ticket()
    else:
        print("Bye!")
        exit(0)

if __name__ == "__main__":
    ae = Toy_AE()
    if not proof_of_work():
        exit(-1)
    for _ in range(4):
        try:
            menu()
        except:
            exit(-1)