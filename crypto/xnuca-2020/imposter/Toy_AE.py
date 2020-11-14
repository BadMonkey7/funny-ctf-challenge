import os
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
from Crypto.Util.number import long_to_bytes, bytes_to_long

class Toy_AE():
    def __init__(self):
        self.block_size = 16
        self.n_size = self.block_size
        self.delta = b'\x00' * self.block_size
        self.init_cipher()

    def init_cipher(self):
        key = os.urandom(16)
        self.cipher = AES.new(key = key, mode = AES.MODE_ECB)

    def pad(self, m, block_size):
        return m if len(m) == block_size else (m + b'\x80' + (b'\x00' * (block_size - 1 - len(m))))

    def GF2_mul(self, a, b, n_size):
        s = 0
        for bit in bin(a)[2:]:
            s = s << 1
            if bit == '1':
                s ^= b
        upper = bytes_to_long(long_to_bytes(s)[:-n_size])
        lower = bytes_to_long(long_to_bytes(s)[-n_size:])
        return upper ^ lower

    def encrypt(self, msg):
        return self.A_EF(msg)

    def decrypt(self, ct, _te):
        msg, te = self.A_DF(ct)
        return msg if _te == te else None

    def A_EF(self, msg):
        self.Sigma = b'\x00' * self.n_size
        self.L = self.cipher.encrypt(b'ConvenienceFixed')
        self.delta = b'DeltaConvenience'
        m = len(msg) // self.n_size
        m += 1 if (len(msg) % self.n_size) else 0
        M_list = [msg[i * self.n_size : (i + 1) * self.n_size] for i in range(m)]
        C_list = []
        for i in range(0, (m-1)//2):
            C1, C2 = self.feistel_enc_2r(M_list[2*i], M_list[2*i +1])
            C_list.append(C1)
            C_list.append(C2)
            self.Sigma = strxor(M_list[2*i +1], self.Sigma)
            self.L = long_to_bytes(self.GF2_mul(2, bytes_to_long(self.L), self.n_size))
        if m & 1 == 0:
            Z = self.cipher.encrypt(strxor(self.L, M_list[-2]))
            Cm  =  strxor(Z[:len(M_list[-1])], M_list[-1])
            Cm_1 = strxor(self.cipher.encrypt(strxor(strxor(self.L, self.delta), self.pad(Cm, self.block_size))), M_list[-2])
            self.Sigma = strxor(self.Sigma, strxor(Z, self.pad(Cm, self.block_size)))
            self.L = strxor(self.L, self.delta)
            C_list.append(Cm_1)
            C_list.append(Cm)
        else:
            Cm = strxor(self.cipher.encrypt(self.L)[:len(M_list[-1])], M_list[-1])
            self.Sigma = strxor(self.Sigma, self.pad(M_list[-1], self.n_size))
            C_list.append(Cm)
        if len(M_list[-1]) == self.n_size:
            multer = strxor(long_to_bytes(self.GF2_mul(3, bytes_to_long(self.L), self.n_size)), self.delta)
        else:
            multer = long_to_bytes(self.GF2_mul(3, bytes_to_long(self.L), self.n_size))
        TE = self.cipher.encrypt(strxor(self.Sigma, multer))
        return b''.join(C_list), TE

    def A_DF(self, ct):
        self.Sigma = b'\x00' * self.n_size
        self.L = self.cipher.encrypt(b'ConvenienceFixed')
        self.delta = b'DeltaConvenience'
        m = len(ct) // self.n_size
        m += 1 if (len(ct) % self.n_size) else 0
        C_list = [ct[i * self.n_size : (i + 1) * self.n_size] for i in range(m)]
        M_list = []
        for i in range(0, (m-1) // 2):
            M1, M2 = self.feistel_dec_2r(C_list[2*i], C_list[2*i +1])
            self.Sigma = strxor(M2 ,self.Sigma)
            self.L = long_to_bytes(self.GF2_mul(2, bytes_to_long(self.L), self.n_size))
            M_list.append(M1)
            M_list.append(M2)
        if m & 1 == 0:
            Mm_1 = strxor(self.cipher.encrypt(strxor(strxor(self.L, self.delta), self.pad(C_list[-1], self.block_size))), C_list[-2])
            Z = self.cipher.encrypt(strxor(self.L, Mm_1))
            Mm = strxor(Z[:len(C_list[-1])], C_list[-1])
            self.Sigma = strxor(self.Sigma, strxor(Z, self.pad(C_list[-1], self.block_size)))
            self.L = strxor(self.L, self.delta)
            M_list.append(Mm_1)
            M_list.append(Mm)
        else:
            Mm = strxor(self.cipher.encrypt(self.L)[:len(C_list[-1])], C_list[-1])
            self.Sigma = strxor(self.Sigma, self.pad(Mm, self.block_size))
            M_list.append(Mm)
        if len(C_list[-1]) == self.n_size:
            multer = strxor(long_to_bytes(self.GF2_mul(3, bytes_to_long(self.L), self.n_size)), self.delta)
        else:
            multer = long_to_bytes(self.GF2_mul(3, bytes_to_long(self.L), self.n_size))
        TE = self.cipher.encrypt(strxor(self.Sigma, multer))
        return b''.join(M_list), TE

    def feistel_enc_2r(self, M1, M2):
        C1 = strxor(self.cipher.encrypt(strxor(M1, self.L)), M2)
        C2 = strxor(self.cipher.encrypt(strxor(C1, strxor(self.L, self.delta))), M1)
        return C1, C2

    def feistel_dec_2r(self, C1, C2):
        M1 = strxor(self.cipher.encrypt(strxor(C1, strxor(self.L, self.delta))), C2)
        M2 = strxor(self.cipher.encrypt(strxor(M1, self.L)), C1)
        return M1, M2