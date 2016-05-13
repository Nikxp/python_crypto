def int_to_str (self, a, sbytesize):
    ans = ''
    for i in range (sbytesize - 1,0, -1):
        ans += chr((a >> i) & 0xff)
    return ans

class VKO:
    def __init__ (self):

    def K (self, x, y, UKM ,yP):
        return ((self.eds.curve.m / self.eds.curve.q * UKM * x )% self.eds.curve.q * yP)

    def KEK (self,x,y,UKM):
        return (self.hash.parsing (self.K (x,y, UKM)))

from EDS import EDS