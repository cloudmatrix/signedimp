#  Copyright (c) 2009-2010, Cloud Matrix Pty. Ltd.
#  All rights reserved; available under the terms of the BSD License.
"""

  signedimp.cryptobase.rsa:  RSA cryto primitives in pure python

"""


# The source for this module might get inlined into some bootstrapping code,
# so we only try these imports if the names aren't already available.


global PSSPadder
try:
    PSSPadder
except NameError:
    from signedimp.cryptobase.pss import RawPadder, PSSPadder, math, _rjust

global sha1
try:
    sha1
except NameError:
    from signedimp.cryptobase.sha1 import sha1


class math(math):
    """Math utilities for RSA, designed to be easily replaced."""

    pow = staticmethod(pow)

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
    _PSS = PSSPadder

    def __init__(self,modulus,pub_exponent,priv_exponent=None,**kwds):
        self._fingerprint = ""
        self.modulus = modulus
        self.pub_exponent = pub_exponent
        self.priv_exponent = priv_exponent
        self.size = self._math.num_bytes(modulus) * 8
        self.randbytes = kwds.pop("randbytes",None)
        self.default_padding_scheme = kwds.pop("default_padding_scheme",None)
        self.allowed_padding_schemes = kwds.pop("allowed_padding_schemes",None)
        self._padders = {}

    def fingerprint(self):
        if not self._fingerprint:
            hash = sha1("RSAKey %s %s" % (self.modulus,self.pub_exponent,))
            self._fingerprint = hash.hexdigest()
        return self._fingerprint

    def get_public_key(self):
        return self.__class__(self.modulus,self.pub_exponent)

    def __getstate__(self):
        state = self.__dict__.copy()
        state.pop("_padders",None)
        return state

    def __setstate__(self,state):
        state["_padders"] = {}
        self.__dict__.update(state)
        if "_fingerprint" not in self.__dict__:
            self._fingerprint = ""

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

    def encrypt(self,message):
        m = self._math.bytes_to_long(message)
        e = self._math.long_to_bytes(self._math.pow(m,self.pub_exponent,self.modulus))
        return e

    def decrypt(self,message):
        m = self._math.bytes_to_long(message)
        d = self._math.long_to_bytes(self._math.pow(m,self.priv_exponent,self.modulus))
        return d

    def sign(self,message,padding_scheme=None):
        if padding_scheme is None:
            padding_scheme = self.default_padding_scheme
        if padding_scheme is None:
            padding_scheme = "pss-sha1"
        encsig = self._get_padder(padding_scheme).encode(message)
        signature = self.decrypt(encsig)
        return padding_scheme + ":" + _rjust(signature,self.size/8,"\x00")

    def verify(self,message,signature):
        try:
            bits = signature.split(":")
            padding_scheme = bits[0]
            signature = ":".join(bits[1:])
        except (ValueError,TypeError,IndexError):
            return False
        signature = _rjust(signature,self.size/8,"\x00")
        encsig = self.encrypt(signature)
        encsig = _rjust(encsig,self.size/8,"\x00")
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
                padder = self._PSS(self.size,self.randbytes)
            elif scheme == "raw":
                padder = RawPadder(self.size,self.randbytes)
            else:
                msg = "unrecognised padding scheme: %s" % (scheme,)
                raise ValueError(msg)
            self._padders[scheme] = padder
        return padder


