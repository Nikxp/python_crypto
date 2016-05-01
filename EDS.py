class EDS:
    def __init__ (self, p, a, b, m, q):
        self.hash = hash()
        return

    def generate (self, mess):
        tmp = self.parsing (mess)
        a = 0
        for i in range (0, len(tmp)):
            a = (a << 8) + ord(tmp [i])
        e = a % q
        if (e == 0):
            e = 1
        OpenSSL.rand.bytes(log(q,2))

        return

from math import log, floor
from hash import hash
import OpenSSL
from math import log
eds = EDS (1,2,3,4,5)
