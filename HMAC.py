class HMAC:
    def __init__ (self, key, block_size = 64):
        self.block_size = block_size
        ipadblock = 0x36
        opadblock = 0x5c
    #    for i in range (0,block_size):
    #        ipad = (ipad << 8) + 0x36
    #        opad = (opad << 8) + 0x5c
        self.key = key
        self.keylen = 0
        self.keystr = ""
        while (key != 0):
            self.keystr = chr(key % 256) + self.keystr
            key >>= 8
            self.keylen += 1
        if (self.keylen > self.block_size):
            self.keyhash = hash()
            self.k0str = self.keyhash.parsing(self.keystr)
            self.k0str += chr(0) * (self.block_size- len(self.k0str))
        else:
            self.k0str = self.keystr  + chr(0) * (self.block_size - len(self.keystr))
            self.kistr = ""
            self.kostr = ""
        for i in range (0, len (self.k0str)):
            self.kistr += chr(ord (self.k0str[i]) ^ ipadblock)
            self.kostr += chr(ord (self.k0str[i]) ^ opadblock)

    def update (self, mess):
        self.hash1 = hash()
        self.hash2 = hash()
        return self.hash2.parsing (self.kostr + self.hash1.parsing(self.kistr + mess))

from hash import hash
hmac = HMAC(657645763634347679806775608787345234612324)
hmac2 = HMAC(88435436467567560000000000000000000000000000000000000000000000007)
print hmac.update("werq")
print hmac2.update ("werq")


