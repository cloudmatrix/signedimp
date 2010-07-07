#  Copyright (c) 2009-2010, Cloud Matrix Pty. Ltd.
#  All rights reserved; available under the terms of the BSD License.
"""

  signedimp.crypto.rsa:  RSA cryto primitives, fast version

"""

import os
from signedimp.cryptobase.rsa import RSAKey, RSAKeyWithPSS, math
from signedimp.crypto.pss import PSS

from math import ceil
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util.number import size as num_bits
from Crypto.PublicKey import RSA as _RSA


class math(math):
    bytes_to_long = staticmethod(bytes_to_long)
    long_to_bytes = staticmethod(long_to_bytes)
    num_bits = staticmethod(num_bits)
    ceil = staticmethod(ceil)
    @staticmethod
    def num_bytes(n):
        b = num_bits(n)
        return int(ceil(b / 8.0))



class RSAKey(RSAKey):
    """Public key using RSS with no padding."""

    _math = math

    @classmethod
    def generate(cls,size=2048,randbytes=os.urandom):
        k = _RSA.generate(size,randbytes)
        return cls(k.n,k.e,k.d)


class RSAKeyWithPSS(RSAKeyWithPSS,RSAKey):
    """Public key using RSS with PSS signature padding scheme."""

    _math = math
    _PSS = PSS

