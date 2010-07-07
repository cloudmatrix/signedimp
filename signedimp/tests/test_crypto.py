

import unittest
from signedimp.tests.test_cryptobase import TestCryptoBase

from signedimp.crypto import md5, sha1, pss, rsa


class TestCrypto(TestCryptoBase):

    md5 = md5
    sha1 = sha1
    pss = pss
    rsa = rsa

