#  Copyright (c) 2009-2010, Cloud Matrix Pty. Ltd.
#  All rights reserved; available under the terms of the BSD License.
"""

  signedimp.cryptobase.rsa:  RSA cryto primitives in pure python

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
    """Public key using RSS with optional padding."""

    _math = math
    _PSS = PSS

    def __init__(self,modulus,pub_exponent,priv_exponent=None,**kwds):
        self.modulus = modulus
        self.pub_exponent = pub_exponent
        self.priv_exponent = priv_exponent
        self.size = self._math.num_bytes(modulus) * 8
        self.randbytes = kwds.pop("randbytes",None)
        self.default_padding_scheme = kwds.pop("default_padding_scheme",None)
        self.allowed_padding_schemes = kwds.pop("allowed_padding_schemes",None)
        self._padders = {}

    def fingerprint(self):
        hash = sha1("RSAKey %s %s" % (self.modulus,self.pub_exponent,))
        return hash.hexdigest()

    def get_public_key(self):
        return self.__class__(self.modulus,self.pub_exponent)

    def __getstate__(self):
        state = self.__dict__.copy()
        state.pop("_padders",None)
        return state

    def __setstate__(self,state):
        state["_padders"] = {}
        self.__dict__.update(state)

    def __eq__(self,other):
        return self.__dict__ == other.__dict__

    def __ne__(self,other):
        return self.__dict__ != other.__dict__

    def __repr__(self):
        s = "%s(%r,%r"%(self.__class__.__name__,self.modulus,self.pub_exponent)
        if self.priv_exponent is not None:
            s += ",%r" % (self.priv_exponent,)
        if self.default_padding_scheme is not None:
            s += ",default_padding_scheme=%r" % (self.default_padding_scheme,)
        if self.allowed_padding_schemes is not None:
            s += ",allowed_padding_schemes=%r" % (self.allowed_padding_schemes,)
        s += ")"
        return s

    def __getstate__(self):
        return self.__dict__.copy()

    def __setstate__(self,state):
        self.__dict__.update(state)

    def encrypt(self,message):
        m = self._math.bytes_to_long(message)
        return self._math.long_to_bytes(pow(m,self.pub_exponent,self.modulus))

    def decrypt(self,message):
        m = self._math.bytes_to_long(message)
        return self._math.long_to_bytes(pow(m,self.priv_exponent,self.modulus))

    def sign(self,message,padding_scheme=None):
        if padding_scheme is None:
            padding_scheme = self.default_padding_scheme
        if padding_scheme is None:
            padding_scheme = "pss-sha1"
        encsig = self._get_padder(padding_scheme).encode(message)
        signature = self.decrypt(encsig)
        return padding_scheme + ":" + signature.rjust(self.size/8,"\x00")

    def verify(self,message,signature):
        try:
            padding_scheme,signature = signature.split(":",1)
        except (ValueError,TypeError):
            return False
        signature = signature.rjust(self.size/8,"\x00")
        encsig = self.encrypt(signature)
        encsig = encsig.rjust(self.size/8,"\x00")
        try:
            padder = self._get_padder(padding_scheme)
        except ValueError:
            return False
        return padder.verify(message,encsig)
        

    def _get_padder(self,scheme):
        if self.allowed_padding_schemes is not None:
            if scheme not in self.allowed_padding_schemes:
                msg = "padding scheme '%s' has been disallowed" % (scheme,)
                raise ValueError(msg)
        try:
            padder = self._padders[scheme]
        except KeyError:
            if scheme == "pss-sha1":
                padder = self._PSS(self.size/8,self.randbytes)
            elif scheme == "raw":
                padder = self._RawPadder(self.size)
            else:
                msg = "unrecognised padding scheme: %s" % (scheme,)
                raise ValueError(msg)
            self._padders[scheme] = padder
        return padder

    class _RawPadder:
        def __init__(self,size):
            self.size = size
        def encode(self,message):
            return message.rjust(self.size/8,"\x00")
        def verify(self,message,signature):
            return (message.rjust(self.size/8,"\x00") == signature)


