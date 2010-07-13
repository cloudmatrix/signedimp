

import unittest
import tempfile

from signedimp.tests.test_cryptobase import TestCryptoBase

from signedimp.crypto import md5, sha1, pss, rsa


class TestCrypto(TestCryptoBase):

    md5 = md5
    sha1 = sha1
    pss = pss
    rsa = rsa


    def test_load_and_save_keys(self):
        cls = self.rsa.RSAKeyWithPSS
        k = cls.generate()
        tf = tempfile.TemporaryFile()
        try:
            k.save_to_file(tf,"hello")
            tf.seek(0)
            self.assertRaises(ValueError,cls.load_from_file,tf,"goodbye")
            tf.seek(0)
            self.assertEquals(k,cls.load_from_file(tf,"hello"))
        finally:
            tf.close()

