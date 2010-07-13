#  Copyright (c) 2009-2010, Cloud Matrix Pty. Ltd.
#  All rights reserved; available under the terms of the BSD License.
"""

  signedimp.crypto.rsa:  RSA cryto primitives, fast version

"""

import os
import struct
import hmac
import hashlib
from math import ceil

import pickle  # yes, I really do need the pure-python version

from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util.number import size as num_bits
from Crypto.PublicKey import RSA as _RSA
from Crypto.Cipher import AES

from signedimp.cryptobase.rsa import RSAKey, RSAKeyWithPSS, math
from signedimp.crypto.pss import PSS, strxor


def hmac_sha1(key,msg=""):
    return hmac.HMAC(key,msg,hashlib.sha1).digest()


def pbkdf2(password,salt,iters,reqlen):
    """Password-Based Key Derivation Function."""
    hlen = len(hmac_sha1(""))
    nchunks = int(ceil(reqlen / float(hlen)))
    res = ""
    for i in xrange(1,nchunks+1):
        chunk = prev = hmac_sha1(password,salt+struct.pack('>L',i))
        for _ in xrange(iters-1):
            prev = hmac_sha1(password,prev)
            chunk = strxor(chunk,prev)
        res += chunk
    return res[:reqlen]
    


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

    def save_to_file(self,f,password):
        """Save to given filelike object, encrypted with given password."""
        #  To save difficulty in unpadding, we add pickle.STOP until we get
        #  to the block size.  This is ignored by the unpickler.
        assert len(pickle.STOP) == 1
        data = pickle.dumps(self)
        while len(data) % AES.block_size != 0:
            data += pickle.STOP
        #  Encrypt the data using derived key and random salt/IV
        salt = os.urandom(8)
        key = pbkdf2(password,salt,1000,24)
        iv = os.urandom(AES.block_size)
        enc_data = AES.new(key,AES.MODE_CBC,iv).encrypt(data)
        #  HMAC the data
        mac_data = hmac_sha1(key,enc_data)
        #  Write out to file, along with metadata necessary to decrypt it.
        f.write("AES CBC SHA1\n")
        f.write("%d %d %d\n" % (24,8,1000,))
        f.write(salt)
        f.write(iv)
        f.write(enc_data)
        f.write(mac_data)
        
    @classmethod
    def load_from_file(cls,f,password):
        """Load from given filelike object, decrypting with given password."""
        #  Read and validate the cipher, mode and hmac types.
        (ctyp,mtyp,htyp) = f.readline().strip().split()
        if ctyp != "AES" or mtyp != "CBC" or htyp != "SHA1":
            raise ValueError("unsupported encryption scheme")
        #  Read and validate the keylen, saltlen and num iters.
        (klen,slen,iters) = map(int,f.readline().strip().split())
        #  Reconsruct the cipher for decryption
        salt = f.read(slen)
        key = pbkdf2(password,salt,iters,klen)
        iv = f.read(AES.block_size)
        cipher = AES.new(key,AES.MODE_CBC,iv)
        #  Split the hmac from the encrypted data
        data = f.read()
        hlen = len(hmac_sha1(""))
        enc_data = data[:-hlen]
        mac_data = data[-hlen:]
        #  Verify then decrypt the data
        if mac_data != hmac_sha1(key,enc_data):
            raise ValueError("invalid hmac")
        data = cipher.decrypt(enc_data)
        #  Finally we can unpickle the key
        return pickle.loads(data)
 
        

class RSAKeyWithPSS(RSAKeyWithPSS,RSAKey):
    """Public key using RSS with PSS signature padding scheme."""

    _math = math
    _PSS = PSS

