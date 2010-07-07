"""

  signedimp.crypto.rsa:  RSA cryto primitives, fast version

"""

from signedimp.cryptobase.rsa import RSAKey, RSAKeyWithPSS, math

from math import ceil
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util.number import size as num_bits

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


class RSAKeyWithPSS(RSAKeyWithPSS):
    """Public key using RSS with PSS signature padding scheme."""

    _math = math

