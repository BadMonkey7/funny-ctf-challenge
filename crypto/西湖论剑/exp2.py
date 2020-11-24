from pwn import *

# context.log_level = "debug"

LOCAL = 1
IP = "127.0.0.1"
PORT = 9999
if LOCAL:
    sh = process(["python","mini_sys2.py"])
else:
    sh = remote(IP,PORT)

sh.recvuntil(b"> ")
sh.sendline(b"root@minisyS")
token = sh.recvline().decode()[6:]

all_hex = '0123456789abcdef'
for i in all_hex:
    for j in all_hex:
        payload = token[:22]+i+token[23:-2]+j
        sh.recvuntil(b"> ")
        sh.sendline(payload.encode())
        res = sh.recvline()
        if b"root@minisys!" in res:
            flag = sh.recvline().decode()
            if "ㄣ零χDそτЬ_ωаnτs_а_ɡíгξfгíěnd╰☆ぷ" not in flag:
                print(flag)
                sh.close()

