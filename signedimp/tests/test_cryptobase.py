
import unittest

import os
import random
import hashlib
import Crypto.Util.number
from Crypto.PublicKey import RSA

from signedimp.cryptobase import md5, sha1, pss, rsa


class TestCryptoBase(unittest.TestCase):

    md5 = md5
    sha1 = sha1
    pss = pss
    rsa = rsa

    def test_bytes_to_long_and_back(self):
        b2l = self.rsa.math.bytes_to_long
        l2b = self.pss.math.long_to_bytes
        self.assertEquals(0,b2l(""))
        self.assertEquals(0,b2l("\x00"))
        self.assertEquals(7,b2l("\x07"))
        self.assertEquals("\x00",l2b(0))
        self.assertEquals("\x07",l2b(7))
        for i in xrange(100):
            ln = random.randint(1,100)
            self.assertEquals(b2l(l2b(ln)),ln)
            bs = os.urandom(ln)
            while bs == "" or bs.startswith("\x00"):
                bs = os.urandom(ln)
            self.assertEquals(l2b(b2l(bs)),bs)
            self.assertEquals(l2b(b2l("\x00\x00"+bs)),bs)
            self.assertEquals(b2l(bs),Crypto.Util.number.bytes_to_long(bs))

    def test_hashes(self):
        HASHES = ((self.md5.md5,hashlib.md5),(self.sha1.sha1,hashlib.sha1))
        for (py,c) in HASHES:
            def pyhash(data):
                return py(data).digest()
            def chash(data):
                return c(data).digest()
            self.assertEquals(pyhash(""),chash(""))
            self.assertEquals(pyhash("foo"),chash("foo"))
            self.assertEquals(pyhash("\x00"),chash("\x00"))
            for i in xrange(100):
                ln = random.randint(1,1000)
                bs = os.urandom(ln)
                self.assertEquals(pyhash(bs),chash(bs))

    def _corrupt(self,data,inv_probability=5):
        newdata = data
        choices = [True] + [False]*(inv_probability-1)
        while newdata == data:
            newbytes = []
            for c in data:
                if random.choice(choices):
                    newbytes.append(chr(random.randint(0,255)))
                else:
                    newbytes.append(c)
            newdata = "".join(newbytes)
        return newdata
                
    def test_rsa_verify(self):
        k = RSA.generate(1024,os.urandom)
        pubkey = self.rsa.RSAKey(k.n,k.e)
        privkey = self.rsa.RSAKey(k.n,k.e,k.d)
        self.assertEquals(pubkey.size,1024)
        self.assertEquals(privkey.size,1024)
        for i in xrange(100):
            ln = random.randint(1,100)
            bs = os.urandom(ln)
            sig = privkey.sign(bs)
            self.assertTrue(pubkey.verify(bs,sig))
            if bs != "\x01":
                self.assertNotEquals(bs,sig)
            self.assertTrue(pubkey.verify(bs,sig))
            self.assertFalse(pubkey.verify(bs,sig+"\x00"))
            self.assertFalse(pubkey.verify(bs,self._corrupt(sig,ln)))
            self.assertFalse(pubkey.verify(bs,self._corrupt(sig,10)))
            self.assertFalse(pubkey.verify(bs,self._corrupt(sig,5)))
            self.assertFalse(pubkey.verify(bs,self._corrupt(sig,1)))
                
    def test_rsawithpss_verify(self):
        k = RSA.generate(1024,os.urandom)
        pubkey = self.rsa.RSAKeyWithPSS(k.n,k.e)
        privkey = self.rsa.RSAKeyWithPSS(k.n,k.e,k.d,randbytes=os.urandom)
        self.assertEquals(pubkey.size,1024)
        self.assertEquals(privkey.size,1024)
        for i in xrange(100):
            ln = random.randint(1,100)
            bs = os.urandom(ln)
            sig = privkey.sign(bs)
            self.assertTrue(pubkey.verify(bs,sig))
            self.assertNotEquals(bs,sig)
            self.assertTrue(pubkey.verify(bs,sig))
            self.assertFalse(pubkey.verify(bs,sig+"\x00"))
            self.assertFalse(pubkey.verify(bs,self._corrupt(sig,ln)))
            self.assertFalse(pubkey.verify(bs,self._corrupt(sig,10)))
            self.assertFalse(pubkey.verify(bs,self._corrupt(sig,5)))
            self.assertFalse(pubkey.verify(bs,self._corrupt(sig,1)))
        


