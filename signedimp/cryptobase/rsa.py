"""

  signedimp.cryptobase.rsa:  RSA cryto primatives in pure python

"""


from signedimp.cryptobase.pss import PSS, math
from signedimp.cryptobase.sha1 import sha1


class math(math):
    """Math utilities for RSA, designed to be easily replaced."""

    @staticmethod
    def bytes_to_long(bytes):
        n = 0
        for b in bytes:
            n = (n << 8) + ord(b)
        return n

    @staticmethod
    def num_bits(n):
        """Calculate the number of bits required to represent n."""
        b = 1
        while 2**b <= n:
            b += 1
        return b 

    @staticmethod
    def num_bytes(n):
        """Calculate the number of bytes required to represent n."""
        b = 1
        while 2**b <= n:
            b += 1
        b = b / 8.0
        intb = int(b)
        if intb == b:
            return intb
        return intb + 1


class RSAKey(object):
    """Public key using RSS with no padding."""

    _math = math

    def __init__(self,modulus,pub_exponent,priv_exponent=None):
        self.modulus = modulus
        self.pub_exponent = pub_exponent
        self.priv_exponent = priv_exponent
        self.size = self._math.num_bytes(modulus) * 8

    def fingerprint(self):
        hash = sha1("RSAKey %s %s" % (self.modulus,self.pub_exponent,))
        return hash.hexdigest()

    def encrypt(self,message):
        m = self._math.bytes_to_long(message)
        return self._math.long_to_bytes(pow(m,self.pub_exponent,self.modulus))

    def decrypt(self,message):
        m = self._math.bytes_to_long(message)
        return self._math.long_to_bytes(pow(m,self.priv_exponent,self.modulus))

    def sign(self,message):
        return self.decrypt(message)

    def verify(self,message,signature):
        while message.startswith("\x00"):
            message = message[1:]
        return (message == self.encrypt(signature))


class RSAKeyWithPSS(RSAKey):
    """Public key using RSS with PSS signature padding scheme."""

    def __init__(self,modulus,pub_exponent,priv_exponent=None,randbytes=None):
        super(RSAKeyWithPSS,self).__init__(modulus,pub_exponent,priv_exponent)
        self._pss = PSS(self.size/8,randbytes=randbytes)

    def fingerprint(self):
        hash = sha1("RSAKeyWithPSS %s %s" % (self.modulus,self.pub_exponent,))
        return hash.hexdigest()

    def sign(self,message):
        encsig = self._pss.encode(message)
        m = self._math.bytes_to_long(encsig)
        signature = pow(m,self.priv_exponent,self.modulus)
        signature = self._math.long_to_bytes(signature)
        return signature.rjust(self.size/8,"\x00")

    def verify(self,message,signature):
        signature = signature.rjust(self.size/8,"\x00")
        m = self._math.bytes_to_long(signature)
        encsig = pow(m,self.pub_exponent,self.modulus)
        encsig = self._math.long_to_bytes(encsig)
        encsig = encsig.rjust(self.size/8,"\x00")
        return self._pss.verify(message,encsig)


