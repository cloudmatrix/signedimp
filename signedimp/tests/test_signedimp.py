
import unittest

import os

import signedimp


class TestSignedImp(unittest.TestCase):


  def test_README(self):
    """Ensure that the README is in sync with the docstring.

    This test should always pass; if the README is out of sync it just updates
    it with the contents of signedimp.__doc__.
    """
    dirname = os.path.dirname
    readme = os.path.join(dirname(dirname(dirname(__file__))),"README.txt")
    if not os.path.isfile(readme):
        f = open(readme,"wb")
        f.write(signedimp.__doc__.encode())
        f.close()
    else:
        f = open(readme,"rb")
        if f.read() != signedimp.__doc__:
            f.close()
            f = open(readme,"wb")
            f.write(signedimp.__doc__.encode())
            f.close()


