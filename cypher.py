from random import SystemRandom

def c_shift_l (number, shift, base):
    return ((number << shift) | ((number << shift) >> base)) & ((1 << base) - 1)


class cypher:
    def __init__ (self, key = 0x0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210, padding_type='PKCS', crypt_type='ECB'):
        self.padding_type = padding_type
        if crypt_type == "CBC":
            self.IV = self.block_to_blockint(self.randomblock())
        self.crypt_type = crypt_type
        self.key = key     # Constant initialization
        self.sbox_init()
        self.crypt_dir = 'f'
    MASK128 = 0xffffffffffffffffffffffffffffffff
    MASK64 = MASK128 >> 64
    MASK32 = MASK64 >> 32
    MASK8 = 0xff
    C1 = 0xA09E667F3BCC908B
    C2 = 0xB67AE8584CAA73B2
    C3 = 0xC6EF372FE94F82BE
    C4 = 0x54FF53A5F1D36F1C
    C5 = 0x10E527FADE682D1D
    C6 = 0xB05688C2B3E6C1FD
    # block_size in char symbols
    block_size = 128 / 8


    def block_to_blockint (self, str):
        a = 0
#        str = self.depadding (str)
        for i in range (0,len (str)):
            a = a * 256 + ord(str[i])
        return a

    def blockint_to_block (self, a):
        str = ""
        mask = 0xff << (8 *(self.block_size - 1))
        for i in range (0, self.block_size):
            str += chr((a & mask) >> (8 *(self.block_size - i - 1)))
            mask >>= 8
        return str
#        str = ""
#        while (a != 0):
#            str = chr(a % 256) + str
#            a //= 256
#        return self.padding(str)

    def randomblock(self):
        return OpenSSL.rand.bytes(int(self.block_size))

    def depadding (self, message):
        if (self.padding_type == 'PKCS') | (self.padding_type == 'ISO') | (self.padding_type == 'ANSI'):
            return message[0:self.block_size - ord(message[len(message) - 1])]

    def padding (self, message):
        if (self.padding_type == 'PKCS'):
            ln = len(message)
            return message + chr(self.block_size - ln) * (self.block_size - ln)
        elif (self.padding_type == 'ISO'):
            ln = len (message)
            message += OpenSSL.rand.bytes(self.block_size - ln)
            return message + chr(self.block_size - ln)
        elif (self.padding_type == 'ANSI'):
            ln = len(message)
            message += chr(0) * (self.block_size - 1 - ln);
            return message + chr(self.block_size - ln)


# sizeof(last_block) in range( 0, blocksize-2)
    def text_encrypt (self, message):
        ans = ""
        if (self.crypt_type == 'ECB'):
            for i in range(0, ((len(message))//self.block_size), 1):
                ans += self.blockint_to_block(self.gen_block_cypher(self.block_to_blockint (message[i*self.block_size:(i + 1)* self.block_size])))
            ln = (len(message)//self.block_size)
            return ans + self.blockint_to_block(self.gen_block_cypher(self.block_to_blockint (self.padding(message[ln*self.block_size:len(message)]))))
        elif (self.crypt_type == 'CBC'):
            self.SV = self.IV
            for i in range(0, (len(message)//self.block_size), 1):
                self.SV = self.gen_block_cypher(self.block_to_blockint (message[i*self.block_size:(i+1)* self.block_size]) ^ (self.SV))
                ans += self.blockint_to_block(self.SV)
            ln = ((len(message))//self.block_size)
            return ans + self.blockint_to_block(self.gen_block_cypher(self.block_to_blockint(self.padding(message[ln*self.block_size:len(message)]))^ self.SV))
#        elif (self.crypt_type == 'CNT')

    def text_decrypt (self,message):
        ans = ""
        if self.crypt_type == 'ECB':
            for i in range(0, ((len(message))//self.block_size) - 1, 1):
                ans += self.blockint_to_block(self.decrypt_block(self.block_to_blockint (message[i*self.block_size:(i + 1)* self.block_size])))
            ln = (len(message)//self.block_size - 1)
            return ans + self.depadding(self.blockint_to_block(self.decrypt_block(self.block_to_blockint (message[ln*self.block_size:len(message)]))))
        if self.crypt_type == 'CBC':
            self.SV = self.IV
            for i in range(0, ((len(message))//self.block_size) - 1, 1):
                ans += self.blockint_to_block(self.decrypt_block(self.block_to_blockint (message[i*self.block_size:(i + 1)* self.block_size])) ^ self.SV)
                self.SV = self.block_to_blockint (message[i*self.block_size:(i + 1)* self.block_size])
            ln = (len(message)//self.block_size - 1)
            return ans + self.depadding(self.blockint_to_block(self.decrypt_block(self.block_to_blockint (message[ln*self.block_size:len(message)])) ^ self.SV))


    def sbox_init(self, csv_file_name="SBox.csv"):
        with open(csv_file_name) as csvfile:
            self.SBox = []
            spamreader = csv.reader(csvfile, quotechar='|')
            for row in spamreader:
                #                SBox_st = []
                for elem in row:
                    self.SBox.append(int(elem))
                    #                    SBox_st.append(elem)
                    #                self.SBox.append(SBox_st)

    def SBox1(self, number):
        return self.SBox[number]

    def SBox2(self, number):
        a = self.SBox[number]
        return (((a & 0x7f) << 1) | (a >> 7))

    def SBox3(self, number):
        a = self.SBox[number]
        return (((a & 1) << 7) | (a >> 1))

    def SBox4(self, number):
        return self.SBox[((number & 0x7f) << 1) | (number >> 7)]

    def sub_func(self, F_IN, KE):
        x = F_IN ^ KE
        t1 = x >> 56
        t2 = (x >> 48) & self.MASK8
        t3 = (x >> 40) & self.MASK8
        t4 = (x >> 32) & self.MASK8
        t5 = (x >> 24) & self.MASK8
        t6 = (x >> 16) & self.MASK8
        t7 = (x >> 8) & self.MASK8
        t8 = x & self.MASK8

        t1 = self.SBox1(t1)
        t2 = self.SBox2(t2)
        t3 = self.SBox3(t3)
        t4 = self.SBox4(t4)
        t5 = self.SBox2(t5)
        t6 = self.SBox3(t6)
        t7 = self.SBox4(t7)
        t8 = self.SBox1(t8)
        y1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8
        y2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8
        y3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8
        y4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7
        y5 = t1 ^ t2 ^ t6 ^ t7 ^ t8
        y6 = t2 ^ t3 ^ t5 ^ t7 ^ t8
        y7 = t3 ^ t4 ^ t5 ^ t6 ^ t8
        y8 = t1 ^ t4 ^ t5 ^ t6 ^ t7
        return (y1 << 56) | (y2 << 48) | (y3 << 40) | (y4 << 32) | (y5 << 24) | (y6 << 16) | (y7 << 8) | y8

    def FL (self, FL_IN, KE):
        x1 = FL_IN >> 32;
        x2 = FL_IN & self.MASK32;
        k1 = KE >> 32;
        k2 = KE & self.MASK32;
        x2 = x2 ^ c_shift_l((x1 & k1),1,32);

        x1 = x1 ^ (x2 | k2);

        return (x1 << 32) | x2;

    def FLINV (self, x, key):
        y1 = x >> 32
        y2 = x & self.MASK32
        k1 = key >> 32
        k2 = key & self.MASK32
        y1 = y1 ^ (y2 | k2)
        y2 = y2 ^ c_shift_l((y1 & k1), 1, 32)
        return (y1 << 32) | y2

    def gen_key(self):
        # KA, KB Calculation
        self.KL = self.key >> 128
        self.KR = self.key & self.MASK128
        D1 = (self.KL ^ self.KR) >> 64
        D2 = (self.KL ^ self.KR) & self.MASK64
        D2 = D2 ^ self.sub_func(D1, self.C1)
        D1 = D1 ^ self.sub_func(D2, self.C2)
        D1 = D1 ^ (self.KL >> 64)
        D2 = D2 ^ (self.KL & self.MASK64)
        D2 = D2 ^ self.sub_func(D1, self.C3)
        D1 = D1 ^ self.sub_func(D2, self.C4)
        self.KA = (D1 << 64) | D2
        D1 = (self.KA ^ self.KR) >> 64
        D2 = (self.KA ^ self.KR) & self.MASK64
        D2 = D2 ^ self.sub_func(D1, self.C5)
        D1 = D1 ^ self.sub_func(D2, self.C6)
        self.KB = (D1 << 64) | D2

    def gen_sub_keys (self):
        self.kw1 = c_shift_l (self.KL , 0, 128) >> 64
        self.kw2 = c_shift_l (self.KL ,   0, 128) & self.MASK64
        self.k1  = c_shift_l (self.KB ,   0, 128) >> 64
        self.k2  = c_shift_l (self.KB ,   0, 128) & self.MASK64
        self.k3  = c_shift_l (self.KR ,  15, 128) >> 64
        self.k4  = c_shift_l (self.KR ,  15, 128) & self.MASK64
        self.k5  = c_shift_l (self.KA ,  15, 128) >> 64
        self.k6  = c_shift_l (self.KA ,  15, 128) & self.MASK64
        self.ke1 = c_shift_l (self.KR ,  30, 128) >> 64
        self.ke2 = c_shift_l (self.KR ,  30, 128) & self.MASK64
        self.k7  = c_shift_l (self.KB ,  30, 128) >> 64
        self.k8  = c_shift_l (self.KB ,  30, 128) & self.MASK64
        self.k9  = c_shift_l (self.KL ,  45, 128) >> 64
        self.k10 = c_shift_l (self.KL ,  45, 128) & self.MASK64
        self.k11 = c_shift_l (self.KA ,  45, 128) >> 64
        self.k12 = c_shift_l (self.KA ,  45, 128) & self.MASK64
        self.ke3 = c_shift_l (self.KL ,  60, 128) >> 64
        self.ke4 = c_shift_l (self.KL ,  60, 128) & self.MASK64
        self.k13 = c_shift_l (self.KR ,  60, 128) >> 64
        self.k14 = c_shift_l (self.KR ,  60, 128) & self.MASK64
        self.k15 = c_shift_l (self.KB ,  60, 128) >> 64
        self.k16 = c_shift_l (self.KB ,  60, 128) & self.MASK64
        self.k17 = c_shift_l (self.KL ,  77, 128) >> 64
        self.k18 = c_shift_l (self.KL ,  77, 128) & self.MASK64
        self.ke5 = c_shift_l (self.KA ,  77, 128) >> 64
        self.ke6 = c_shift_l (self.KA ,  77, 128) & self.MASK64
        self.k19 = c_shift_l (self.KR ,  94, 128) >> 64
        self.k20 = c_shift_l (self.KR ,  94, 128) & self.MASK64
        self.k21 = c_shift_l (self.KA ,  94, 128) >> 64
        self.k22 = c_shift_l (self.KA ,  94, 128) & self.MASK64
        self.k23 = c_shift_l (self.KL , 111, 128) >> 64
        self.k24 = c_shift_l (self.KL , 111, 128) & self.MASK64
        self.kw3 = c_shift_l (self.KB , 111, 128) >> 64
        self.kw4 = c_shift_l (self.KB , 111, 128) & self.MASK64


    def gen_block_cypher(self, message):
        if (self.crypt_dir == 'b'):
            self.kw1, self.kw3 = self.kw3, self.kw1
            self.kw2, self.kw4 = self.kw4, self.kw2
            self.k1 , self.k24 = self.k24, self.k1
            self.k2 , self.k23 = self.k23, self.k2
            self.k3 , self.k22 = self.k22, self.k3
            self.k4 , self.k21 = self.k21, self.k4
            self.k5 , self.k20 = self.k20, self.k5
            self.k6 , self.k19 = self.k19, self.k6
            self.k7 , self.k18 = self.k18, self.k7
            self.k8 , self.k17 = self.k17, self.k8
            self.k9 , self.k16 = self.k16, self.k9
            self.k10, self.k15 = self.k15, self.k10
            self.k11, self.k14 = self.k14, self.k11
            self.k12, self.k13 = self.k13, self.k12
            self.ke1, self.ke6 = self.ke6,self.ke1
            self.ke2, self.ke5 = self.ke5,self.ke2
            self.ke3, self.ke4 = self.ke4,self.ke3
            self.crypt_dir = 'f'
        D1 = message >> 64
        D2 = message & self.MASK64
        D1 = D1 ^ self.kw1
        D2 = D2 ^ self.kw2
        D2 = D2 ^ self.sub_func(D1, self.k1)
        D1 = D1 ^ self.sub_func(D2, self.k2)
        D2 = D2 ^ self.sub_func(D1, self.k3)
        D1 = D1 ^ self.sub_func(D2, self.k4)
        D2 = D2 ^ self.sub_func(D1, self.k5)
        D1 = D1 ^ self.sub_func(D2, self.k6)
        D1 = self.FL   (D1, self.ke1)
        D2 = self.FLINV(D2, self.ke2)
        D2 = D2 ^ self.sub_func(D1, self.k7)
        D1 = D1 ^ self.sub_func(D2, self.k8)
        D2 = D2 ^ self.sub_func(D1, self.k9)
        D1 = D1 ^ self.sub_func(D2, self.k10)
        D2 = D2 ^ self.sub_func(D1, self.k11)
        D1 = D1 ^ self.sub_func(D2, self.k12)
        D1 = self.FL   (D1, self.ke3)
        D2 = self.FLINV(D2, self.ke4)
        D2 = D2 ^ self.sub_func(D1, self.k13)
        D1 = D1 ^ self.sub_func(D2, self.k14)
        D2 = D2 ^ self.sub_func(D1, self.k15)
        D1 = D1 ^ self.sub_func(D2, self.k16)
        D2 = D2 ^ self.sub_func(D1, self.k17)
        D1 = D1 ^ self.sub_func(D2, self.k18)
        D1 = self.FL   (D1, self.ke5)
        D2 = self.FLINV(D2, self.ke6)
        D2 = D2 ^ self.sub_func(D1, self.k19)
        D1 = D1 ^ self.sub_func(D2, self.k20)
        D2 = D2 ^ self.sub_func(D1, self.k21)
        D1 = D1 ^ self.sub_func(D2, self.k22)
        D2 = D2 ^ self.sub_func(D1, self.k23)
        D1 = D1 ^ self.sub_func(D2, self.k24)
        D2 = D2 ^ self.kw3
        D1 = D1 ^ self.kw4
        return (D2 << 64) | D1

    def decrypt_block(self, message):
        if (self.crypt_dir == 'f'):
            self.kw1, self.kw3 = self.kw3, self.kw1
            self.kw2, self.kw4 = self.kw4, self.kw2
            self.k1 , self.k24 = self.k24, self.k1
            self.k2 , self.k23 = self.k23, self.k2
            self.k3 , self.k22 = self.k22, self.k3
            self.k4 , self.k21 = self.k21, self.k4
            self.k5 , self.k20 = self.k20, self.k5
            self.k6 , self.k19 = self.k19, self.k6
            self.k7 , self.k18 = self.k18, self.k7
            self.k8 , self.k17 = self.k17, self.k8
            self.k9 , self.k16 = self.k16, self.k9
            self.k10, self.k15 = self.k15, self.k10
            self.k11, self.k14 = self.k14, self.k11
            self.k12, self.k13 = self.k13, self.k12
            self.ke1, self.ke6 = self.ke6,self.ke1
            self.ke2, self.ke5 = self.ke5,self.ke2
            self.ke3, self.ke4 = self.ke4,self.ke3
            self.crypt_dir = 'b'
        D1 = message >> 64
        D2 = message & self.MASK64
        D1 = D1 ^ self.kw1
        D2 = D2 ^ self.kw2
        D2 = D2 ^ self.sub_func(D1, self.k1)
        D1 = D1 ^ self.sub_func(D2, self.k2)
        D2 = D2 ^ self.sub_func(D1, self.k3)
        D1 = D1 ^ self.sub_func(D2, self.k4)
        D2 = D2 ^ self.sub_func(D1, self.k5)
        D1 = D1 ^ self.sub_func(D2, self.k6)
        D1 = self.FL   (D1, self.ke1)
        D2 = self.FLINV(D2, self.ke2)
        D2 = D2 ^ self.sub_func(D1, self.k7)
        D1 = D1 ^ self.sub_func(D2, self.k8)
        D2 = D2 ^ self.sub_func(D1, self.k9)
        D1 = D1 ^ self.sub_func(D2, self.k10)
        D2 = D2 ^ self.sub_func(D1, self.k11)
        D1 = D1 ^ self.sub_func(D2, self.k12)
        D1 = self.FL   (D1, self.ke3)
        D2 = self.FLINV(D2, self.ke4)
        D2 = D2 ^ self.sub_func(D1, self.k13)
        D1 = D1 ^ self.sub_func(D2, self.k14)
        D2 = D2 ^ self.sub_func(D1, self.k15)
        D1 = D1 ^ self.sub_func(D2, self.k16)
        D2 = D2 ^ self.sub_func(D1, self.k17)
        D1 = D1 ^ self.sub_func(D2, self.k18)
        D1 = self.FL   (D1, self.ke5)
        D2 = self.FLINV(D2, self.ke6)
        D2 = D2 ^ self.sub_func(D1, self.k19)
        D1 = D1 ^ self.sub_func(D2, self.k20)
        D2 = D2 ^ self.sub_func(D1, self.k21)
        D1 = D1 ^ self.sub_func(D2, self.k22)
        D2 = D2 ^ self.sub_func(D1, self.k23)
        D1 = D1 ^ self.sub_func(D2, self.k24)
        D2 = D2 ^ self.kw3
        D1 = D1 ^ self.kw4
        return (D2 << 64) | D1

hw = "Hello, world!"
print (hw)
import csv

import OpenSSL

cyph = cypher(0x1123456789abcdeffedcba98765432101123456789abcdeffedcba9876543210,"PKCS","CBC")
cyph.gen_key()
cyph.gen_sub_keys()
#print cyph.block_to_int(cyph.int_to_block(12))
#a =cyph.gen_block_cypher(0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)
#print(hex(a))
#print(hex(cyph.decrypt_block(a)))
#print cyph.text_decrypt(cyph.text_encrypt ("Privet, Gleb. Vidiw eto soobshenie. 19:50 ECB, PCSC. Ydachi i spokoinoi nochi. Vot. re"))




