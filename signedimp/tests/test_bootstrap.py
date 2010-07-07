
import unittest

import os
import random

from signedimp.bootstrap import _signedimp_b64decode as bs_b64decode
import base64


class TestBootstrap(unittest.TestCase):

    def test_b64_decode(self):
        for i in xrange(100):
            ln = random.randint(1,100)
            bs = os.urandom(ln)
            self.assertEquals(bs_b64decode(base64.b64encode(bs)),bs)

