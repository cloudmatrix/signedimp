#  Copyright (c) 2009-2010, Cloud Matrix Pty. Ltd.
#  All rights reserved; available under the terms of the BSD License.
"""

  signedimp.crypto.pss:  the PSS padding algorithm for RSA, fast version

"""

from signedimp.cryptobase.pss import PSS, make_mgf1

from math import ceil
from Crypto.Util.number import long_to_bytes
try:
    from Crypto.Util.strxor import strxor
except ImportError:
    from Crypto.Hash.HMAC import _strxor as strxor

class math:
    ceil = staticmethod(ceil)
    long_to_bytes = staticmethod(long_to_bytes)
    strxor = staticmethod(strxor)


try:
    from hashlib import sha1
except ImportError:
    import sha
    sha1 = sha.new
    del sha


randbytes = None
def load_urandom():
    """Try to load and return the os.urandom function.

    Note that it's possible for this function to exist but not be
    usable, so we test this by consuming a single random byte.
    To use a different source of randomness by default, bind the
    global 'randbytes' variable to an appropriate function.
    """
    global randbytes
    if randbytes is None:
        import os
        try:
            os.urandom(1)
        except (AttributeError,NotImplementedError):
            raise RuntimeError("Could not load os.urandom")
        randbytes = os.urandom
    return randbytes



MGF1_SHA1 = make_mgf1(sha1,math=math)


class PSS(PSS):
    """Class implementing PSS encoding/verifying, fast version.

    This class can be used to encode/verify message signatures using the
    Proabilistic Signature Scheme.  The method 'encode' will encode a byte
    string into a signature, while the method 'verify' will confirm that
    a signature matches a given byte string.

    The algorithms are from PKCS#1 version 2.1, section 9.1
    """

    _math = math

    def __init__(self,size,randbytes=None,hash=sha1,mgf=MGF1_SHA1,saltlen=8):
        """Initialize a PSS object.

        You must specify the size of the key modulus in bytes.  Optional
        arguments include a source of random bytes, hash function, mask
        generation function, and salt length.
        """
        if randbytes is None:
            randbytes = load_urandom()
        super(PSS,self).__init__(size,randbytes,hash,mgf,saltlen)

