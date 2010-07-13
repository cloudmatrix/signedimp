
import unittest

import os
import random

# Careful, we must import this before importing base64, it it will pick
# up on the availability of the builtin version and use it directly.
from signedimp.bootstrap import _signedimp_util
bs_b64decode = _signedimp_util.b64decode

import base64

class TestBootstrap(unittest.TestCase):

    def test_b64_decode(self):
        self.assertEquals(_signedimp_util.b64decode(base64.b64encode("")),"")
        self.assertEquals(_signedimp_util.b64decode(base64.b64encode("\x00")),"\x00")
        self.assertEquals(_signedimp_util.b64decode(base64.b64encode("\x00hello\x00")),"\x00hello\x00")
        for i in xrange(100):
            ln = random.randint(1,100)
            bs = os.urandom(ln)
            self.assertEquals(_signedimp_util.b64decode(base64.b64encode(bs)),bs)

