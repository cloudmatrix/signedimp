#  Copyright (c) 2009-2010, Cloud Matrix Pty. Ltd.
#  All rights reserved; available under the terms of the BSD License.
"""

  signedimp.crypto.pss:  the PSS padding algorithm for RSA, from PKCS#1

This module implements the the PSS padding algorithms for use with RSA message
signing, taken directly from PKCS#1.

The default hash function used by this module is sha1.  If you really want
to muck around with another hash function, you can use the function make_mgf1
to construct its corresponding mask generation function and pass these
as optional arguments to the encoding classes.

Encoding under this scheme requires a strong source of random bytes.  Since 
this module must be import-less pure python, it cannot obtain such bytes 
automatically.  You must either (1) explicitly specify the 'randbytes' argument
when constructing a PSS instance or (2) bind the name 'randbytes' in this
module to an appropriate function.

"""


from signedimp.cryptobase.sha1 import sha1

class math:
    """Math utilities for PSS, designed to be easily replaced."""

    @staticmethod
    def ceil(n):
        c = int(n)
        if c == n:
            return c
        return c + 1

    @staticmethod
    def long_to_bytes(n):
        bytes = []
        while n > 0:
            bytes.append(chr(n & 0x000000FF))
            bytes.append(chr((n & 0x0000FF00) >> 8))
            bytes.append(chr((n & 0x00FF0000) >> 16))
            bytes.append(chr((n & 0xFF000000) >> 24))
            n = n >> 32
        bytes = "".join(reversed(bytes))
        for i in xrange(len(bytes)):
            if bytes[i] != "\x00":
                return bytes[i:]
        else:
            return "\x00"

    @staticmethod
    def strxor(s1,s2):
        return "".join(map(lambda x, y: chr(ord(x) ^ ord(y)), s1, s2))


def make_mgf1(hash,math=math):
    """Make an MFG1 function using the given hash function.

    Given a hash function implementing the standard hash function interface,
    this function returns a Mask Generation Function using that hash.
    """
    def mgf1(mgfSeed,maskLen):
        """Mask Generation Function based on a hash function.

        Given a seed byte string 'mgfSeed', this function will generate
        and return a mask byte string  of length 'maskLen' in a manner
        approximating a Random Oracle.

        The algorithm is from PKCS#1 version 2.1, appendix B.2.1.
        """
        hLen = hash().digest_size
        if maskLen > 2**32 * hLen:
            raise ValueError("mask too long")
        T = ""
        for counter in range(int(math.ceil(maskLen / (hLen*1.0)))):
            C = math.long_to_bytes(counter)
            C = ('\x00'*(4 - len(C))) + C
            assert len(C) == 4, "counter was too big"
            T += hash(mgfSeed + C).digest()
        assert len(T) >= maskLen, "generated mask was too short"
        return T[:maskLen]
    return mgf1


MGF1_SHA1 = make_mgf1(sha1)


class PSS(object):
    """Class implementing PSS encoding/verifying.

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
        self.size = size
        if randbytes is None:
            randbytes = globals().get("randbytes",None)
        self.randbytes = randbytes
        self.hash = hash
        self.mgf = mgf
        self.salt_length = saltlen

    def encode(self,M):
        """Encode the message M into a signature."""
        emBits = self.size*8 - 1
        emLen = int(self._math.ceil(emBits / 8.0))
        sLen = self.salt_length
        #  Generate the message hash
        mHash = self.hash(M).digest()
        hLen = len(mHash)
        #  Check the message lengths
        if emLen < hLen + sLen + 2:
            raise ValueError("encoding error")
        #  Generate the salted message hash
        salt = self.randbytes(sLen)
        M1 = "\0"*8 + mHash + salt
        H = self.hash(M1).digest()
        #  Perform the masking etc
        PS = "\0" * (emLen - sLen - hLen - 2)
        DB = PS + "\x01" + salt
        dbMask = self.mgf(H,emLen - hLen - 1)
        maskedDB = self._math.strxor(DB,dbMask)
        #  Since we calculate emBits using the key size in bytes, 
        #  (8*emLen - emBits) is always 1.   WE only need to
        #  zero the leading bit in maskedDB. 
        maskedDB = chr(ord(maskedDB[0]) & 127) + maskedDB[1:]
        EM = maskedDB + H + "\xbc"
        return EM

    def verify(self,M,EM):
        """Verify that EM is the signature of message M."""
        emBits = self.size*8 - 1
        emLen = int(self._math.ceil(emBits / 8.0))
        sLen = self.salt_length
        #  Generate the message hash
        mHash = self.hash(M).digest()
        hLen = len(mHash)
        #  Do various well-formedness checks
        if emLen < hLen + sLen + 2:
            return False
        if EM[-1] != "\xbc":
            return False
        #  Deconstruct the signature into its parts
        maskedDB = EM[:emLen-hLen-1]
        H = EM[emLen-hLen-1:emLen-1]
        #  Check that the first bit is zeroed.  As discussed in encode(),
        #  (8*emLen - emBits) is always 1 in this implementation.
        if (ord(maskedDB[0]) & 128) != 0:
            return False
        #  Unmask the DB string.
        dbMask = self.mgf(H,emLen - hLen - 1)
        DB = self._math.strxor(maskedDB,dbMask)
        DB = chr(ord(DB[0]) & 127) + DB[1:]
        #  Check for well-formedness of DB
        for c in DB[:emLen-hLen-sLen-2]:
            if c != "\0":
                return False
        if DB[emLen-hLen-sLen-2] != "\x01":
            return False
        #  Re-construct and verify the message hash
        salt = DB[-1*sLen:]
        M1 = "\0"*8 + mHash + salt
        H1 = self.hash(M1).digest()
        if H != H1:
            return False
        return True

