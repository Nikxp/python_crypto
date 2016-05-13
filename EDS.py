def str_to_int (mess):
    res = 0
    for i in range (0, len(mess)):
        res = (res << 8) + ord(mess[i])
    return res

def div (x, p):
    psup = p
    a = 0
    b = 1
    rem = -1
    while (x != 0):
        rem = - rem
        psup, x, a, b = x, psup % x, b, (psup // x) * b + a
    return (a * rem % p);

class el_curve:
    def __init__ (self,
                  a = 7,
                  b = 0x5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E,
                  p = 0x8000000000000000000000000000000000000000000000000000000000000431,
                  q = 0x8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3,
                  m = 0x8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3):
        if ((4 * a**3) + (27 * b * b)) % p == 0:
            return -1
        self.q = q
        self.a = a
        self.b = b
        self.p = p
        self.m = m
        self.ptr = []

    def ptr_add (self, x, y):
        self.ptr.append (ellipse_ptr(x,y))

    def sum_ptr (self, i , j):
        if (j is None):
            res = i
        elif (i is None):
            res = j
        elif (i.x != j.x):
            lamda = ((j.y - i.y) % self.p) * div((j.x - i.x) % self.p, self.p)
            x3 = (lamda * lamda -  i.x - j.x) % self.p
            res = ellipse_ptr(x3, lamda * (i.x - x3) - i.y, self.p)
        elif (i.y == j.y) & (j.y != 0):
            lamda = (3 * i.x * i.x + self.a) * div(2 * i.y % self.p, self.p)
            x3 = (lamda * lamda - 2 * i.x) % self.p
            res = ellipse_ptr(x3,(lamda* (i.x - x3) - i.y) % self.p)
        elif (i.y % self.p == (-j.y) % self.p):
            res = None;
        else:
            print "Error in function sum_ptr"
        return res

    def twice_ptr (self, i):
        if (i is None):
            return i
        lamda = (3 * i.x * i.x + self.a) * div(2 * i.y % self.p, self.p)
        x3 = (lamda * lamda - 2 * i.x) % self.p
        res = ellipse_ptr(x3,(lamda* (i.x - x3) - i.y) % self.p)
        return res


    def mul_ptr (self,i,k):
        res = None
        tmp = 1 << (int(floor(log(k,2))))
        while (tmp != 0):
            res = self.twice_ptr (res)
            if ((tmp & k) != 0):
                res = self.sum_ptr (res, i)
            tmp >>= 1
        return res

class ellipse_ptr:
    def __init__ (self,
                  p,
                  x = 0x2,
                  y = 0x8E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8):
        self.x = x % p
        self.y = y % p


class EDS:
    def __init__ (self, d =0x7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28):
        self.hash = hash()
        self.curve = el_curve ()
        self.ptr_p = ellipse_ptr(self.curve.p)
        self.d = d
        return

    def gen_q (self):
        return (self.curve.mul_ptr(self.ptr_p, self.d))

    def generate (self, mess):
        tmp = self.hash.parsing (mess)
        a = 0
        for i in range (0, len(tmp)):
            a = (a << 8) + ord(tmp [i])
        e = a % self.curve.q
        if (e == 0):
            e = 1
        r = 0
        s = 0
        while (s == 0):
            while (r == 0):
                """
                tmp = self.curve.q
                tmplen = 0
                while (tmp != 0):
                    tmplen += 1
                    tmp >>= 8
                tmpstr = OpenSSL.rand.bytes(tmplen - 1)
                """
                tmpstr = OpenSSL.rand.bytes(int(floor(log(self.curve.q,256)) - 1))
                k = str_to_int(tmpstr)
#                for i in range (0, len(tmpstr)):
#                    k = (k << 8) + ord (tmpstr[i])
                ptr_pk = self.curve.mul_ptr (self.ptr_p, k)
                r = ptr_pk.x % self.curve.q
            s = (r * self.d + k * e) % self.curve.q
        ans = ""
        for i in range (0, 256):
            ans = chr (r % 256) + ans
            r >>= 8
        for i in range (0, 256):
            ans = chr (s % 256) + ans
            s >>= 8
        return ans

    def check (self, mess, rs, ptr_q):
        r = str_to_int(rs[0:256])
        s = str_to_int(rs[256:512])
        if not ((r < self.curve.q) & (s <self.curve.q)):
            return None
        h = self.hash.parsing (mess)
        e = str_to_int(h) % self.curve.q
        if (e == 0):
            e = 1
        v = div(e,self.curve.q)
        z1 = s * v % self.curve.q
        z2 = (- (r * v)) % self.curve.q
        C = self.curve.sum_ptr(self.curve.mul_ptr(self.ptr_p, z1),self.curve.mul_ptr (ptr_q, z2))
        R = C.x % self.curve.q
        if R != r:
            return None
        return 0;

from math import log, floor
from hash import hash
import OpenSSL
from math import log
print div (3,19)
eds = EDS ()
print eds.check("1234567890",eds.generate("1234567890"),eds.gen_q())
