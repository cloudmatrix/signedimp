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
automatically.  You must explicitly specify the 'randbytes' argument when
constructing a PSS instance.

"""


import sys

global sha1
try:
    sha1
except NameError:
    if "_sha" in sys.builtin_module_names:
        import _sha
        sha1 = _sha.new
    else:
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
        return "".join([chr(ord(x) ^ ord(y)) for (x,y) in zip(s1,s2)])


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
        hLen = len(hash().digest())
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


class Padder(object):
    """Generic base class for RSA padder objects."""

    def __init__(self,size,randbytes):
        self.size = size
        self.randbytes = randbytes


class RawPadder(Padder):
    """Padder implementation that just adds null bytes."""

    def encode(self,message):
        return _rjust(message,self.size/8,"\x00")

    def verify(self,message,signature):
        return (_rjust(message,self.size/8,"\x00") == signature)



class PSSPadder(Padder):
    """Class implementing PSS encoding/verifying.

    This class can be used to encode/verify message signatures using the
    Proabilistic Signature Scheme.  The method 'encode' will encode a byte
    string into a signature, while the method 'verify' will confirm that
    a signature matches a given byte string.

    The algorithms are from PKCS#1 version 2.1, section 9.1
    """

    _math = math

    def __init__(self,size,randbytes,hash=None,mgf=None,saltlen=8):
        """Initialize a PSS object.

        You must specify the size of the key modulus in bytes.  Optional
        arguments include a source of random bytes, hash function, mask
        generation function, and salt length.
        """
        Padder.__init__(self,size,randbytes)
        if hash is None:
            hash = sha1
        self.hash = hash
        if mgf is None:
            mgf = MGF1_SHA1
        self.mgf = mgf
        self.salt_length = saltlen

    def __eq__(self,other):
        return self.__dict__ == other.__dict__

    def encode(self,M):
        """Encode the message M into a signature."""
        emBits = self.size - 1
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
        emBits = self.size - 1
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
        maskEnd = emLen - hLen - 1
        assert maskEnd > 0
        maskedDB = EM[:maskEnd]
        hashEnd = emLen - 1
        assert hashEnd > 0
        H = EM[maskEnd:hashEnd]
        #  Check that the first bit is zeroed.  As discussed in encode(),
        #  (8*emLen - emBits) is always 1 in this implementation.
        if (ord(maskedDB[0]) & 128) != 0:
            return False
        #  Unmask the DB string.
        dbMask = self.mgf(H,emLen - hLen - 1)
        DB = self._math.strxor(maskedDB,dbMask)
        DB = chr(ord(DB[0]) & 127) + DB[1:]
        #  Check for well-formedness of DB
        checkEnd = emLen - hLen - sLen - 2
        assert checkEnd > 0
        for c in DB[:checkEnd]:
            if c != "\0":
                return False
        if DB[emLen-hLen-sLen-2] != "\x01":
            return False
        #  Re-construct and verify the message hash
        saltStart = len(DB) - sLen
        assert saltStart > 0
        salt = DB[saltStart:]
        M1 = "\0"*8 + mHash + salt
        H1 = self.hash(M1).digest()
        if H != H1:
            return False
        return True


def _rjust(string,size,pad=" "):
    """Right-justify a string to the given size.

    This is a re-implementation for RPython compatability, as they don't
    seem to have implemented rjust.
    """
    if len(string) >= size:
        return string
    extra = pad * (size - len(string))
    return extra + string


