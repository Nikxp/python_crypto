class hash:
    def __init__ (self, block_size = 512/8):
        self.block_size = block_size
        self.h = []
        self.const_init_IV()
        self.const_init_per()
        self.const_init_c()
        return

    def gen_salt (self,ch = ""):
        self.salt = [0,0,0,0,0,0,0,0]

    def intblock_to_block (self, a):
        ans = ""
        while (a != 0):
            b = a % (256)
            ans =  chr(b) + ans
            a >>= 8
        return chr(0) * (self.block_size-len(ans)) + ans

    def block_to_int (self, block):
        a = 0
        for i in range (0,len (block)):
            a = a * 256 + ord(block[i])
        return a

    def parsing (self, mess):
        for i in range (0, 8):
            self.h.append(self.IV[i])
        self.gen_salt()
        self.counter = 0;
        if (len (mess) * 8 < 447):
            self.compress(self.padding(self.block_to_int(mess), len(mess) * 8))
        else:
            for i in range (0, len(mess) // self.block_size):
                self.compress(self.block_to_int(mess[i * self.block_size:(i+1) * self.block_size]))
            if len(mess) % self.block_size == 0:
                self.compress(self.block_to_int(mess[(len(mess) // self.block_size) * self.block_size:len(mess)]))
                self.compress(self.block_to_int(""))
            elif (len(mess) * 8 < 447):
                self.compress(self.padding(self.block_to_int(mess[(len(mess) // self.block_size) * self.block_size:len(mess)]),len(mess) * 8))
            else:
                self.compress(self.block_to_int(mess[(len(mess) // self.block_size) * self.block_size:len(mess)] + chr(0x80)))
                self.compress(self.block_to_int(""))
        ans = ""
        for i in range (0,7):
            ans += self.intblock_to_block(self.h[i])
        return ans

    def padding (self, block, mes_len):
        temp = block
        if (mes_len % 512 == 0):
            block = mes_len + (1 << 64) + (1 << 511)
            return block
        elif ((mes_len % 512) < 447):
            len = 0
            while (temp != 0):
                temp >>= 1
                len += 1
            block = ((block << 1) + 1 )<< (self.block_size * 8 - 1 - len)
            mes_len += 1 << 64
            block += mes_len
            return block
        else:
            block = mes_len + (1 << 64)
            return block



    def compress (self, mess):
        #initialization
        self.v = self.h
        for i in range (8, 12):
            self.v.append( self.salt[i - 8] ^ self.c[i - 8])
        for i in range (12, 16):
            self.v.append(((self.counter &((0x1f) << 5 *((i - 12) // 2))) >> (5 * ((i - 12) // 2))) ^ self.c[i-8])
        #rounds
        for i in range (0,14):
#            print (self.v)
            self.round(i, mess);
        #finalization
        for i in range (0,8):
            self.h[i] ^= self.salt[i % 4] ^ self.v[8 + i]
        self.counter += 1

    def round (self, rnd, mess):
        for i in range (0,4):
            j = self.per[rnd % 10][2 * i]
            k = self.per[rnd % 10][2* i + 1]
            mj = (mess >> (5 * j)) & 0x1f
            mk = (mess >> (5 * k)) & 0x1f
            self.G(i,i+4,i+8,i+12, j, k, mj, mk)
        for i in range (0,4):
            j = self.per[rnd % 10][2 * i]
            k = self.per[rnd % 10][2* i + 1]
            self.G(i,4 + ((i+ 1)%4), 8 + ((i+2)%4),12 + ((i+3)%4), j, k, mj, mk)

    def G (self, a, b, c, d, j, k, mj, mk):
        self.v[a] = self.v[a] + self.v[b] +((mj) ^ self.c[k])
        self.v[d] = c_shift_l ((self.v[d] ^ self.v[a]), 16, 32)
        self.v[c] = self.v[c] + self.v[d]
        self.v[b] = c_shift_l((self.v[b] + self.v[c]), 20, 32)
        self.v[a] = self.v[a] + self.v[b] + (mk ^ self.c[j])
        self.v[d] = c_shift_l((self.v[d] ^ self.v[a]), 24, 32)
        self.v[c] = self.v[c] + self.v[d]
        self.v[b] = c_shift_l(self.v[b] ^self.v[c],25, 32)

    def const_init_IV (self, csv_file_name = "hash_IV.csv"):
        with open(csv_file_name) as csvfile:
            self.IV = []
            spamreader = csv.reader(csvfile, quotechar='|')
            for row in spamreader:
                for elem in row:
                    self.IV.append(int(elem,16))

    def const_init_per (self, csv_file_name = "hash_per.csv"):
        with open (csv_file_name) as csvfile:
            self.per = []
            spamreader = csv.reader(csvfile, quotechar = '|')
            i = 0
            for row in spamreader:
                self.per.append([])
                for elem in row:
                    self.per[i].append(int(elem))
                i += 1

    def const_init_c (self, csv_file_name = "hash_c.csv"):
        with open (csv_file_name) as csvfile:
            self.c = []
            spamreader = csv.reader(csvfile, quotechar = '|')
            for row in spamreader:
                for elem in row:
                    self.c.append(int(elem,16))

import csv
#import OpenSSL
from cypher import c_shift_l
#has = hash();
#print has.parsing("")