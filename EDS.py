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
    def __init__ (self, a, b, p, q):
        if ((4 * a**3) + (27 * b * b)) % p == 0:
            return -1
        self.q = q
        self.a = a
        self.b = b
        self.p = p
        self.ptr = []

    def ptr_add (self, x, y):
        self.ptr.append (ellipse_ptr(x,y))

    def sum_ptr (self, i , j):
        if (i.x != j.x):
            lamda = ((j.y - i.y) % self.p) * div((j.x - i.x) % self.p, self.p)
            x3 = (lamda * lamda -  i.x - j.x) % self.p
            res = ellipse_ptr(x3, lamda * (i.x - x3) - i.y, self.p)
        elif (i.y == j.y) & (j.y != 0):
            lamda = (3 * i.x * i.x + self.a) * div(2 * i.y % self.p, self.p)
            x3 = (lamda * lamda - 2 * i.x) % self.p
            res = ellipse_ptr(x3,(lamda* (i.x - x3) - j.y) % self.p)
        elif (i.y % self.p == (-j.y) % self.p):
            res = None;
        elif (i is None):
            res = j
        elif (j is None):
            res = i
        return res

    def mul_ptr (self,i,k):
        res = i
        for j in range (0,k):
            res = self.sum_ptr (i, res)
        return res

class ellipse_ptr:
    def __init__ (self,x = 0, y = 0, p = 1):
        self.x = x % p
        self.y = y % p
        return

class EDS:
    def __init__ (self, p, a, b, m, q):
        self.hash = hash()
        self.curve = el_curve ()
        return

    def generate (self, mess):
        tmp = self.parsing (mess)
        a = 0
        for i in range (0, len(tmp)):
            a = (a << 8) + ord(tmp [i])
        e = a % q
        if (e == 0):
            e = 1
        r = 0
        s = 0
        while (s == 0):
            while (r == 0):
                tmpstr = OpenSSL.rand.bytes(floor(log(q,2)) - 1)
                for i in range (0, len(tmpstr)):
                    k = (k << 8) + ord (tmpstr[i])
                ptr_pk = self.curve.mul_ptr (ptr_p, k)
                r = ptr_pk.x % q
            s = (r * d + k * e) % q
        ans = ""
        for i in range (0, 256):
            ans = chr (r % 256) + ans
            r >>= 8
        for i in range (0, 256):
            ans = chr (s % 256) + ans
            s >>= 8
        return ans


from math import log, floor
from hash import hash
import OpenSSL
from math import log
print div (3,19)
#eds = EDS (1,2,3,4,5)
