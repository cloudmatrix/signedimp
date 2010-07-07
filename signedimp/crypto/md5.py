"""

  signedimp.crypto.md5:  the MD5 hashing alorithm, fast version.

"""

try:
    from hashlib import md5
except ImportError:
    try:
        from Crypto.Hash import MD5
        md5 = MD5.new
    except ImportError:
        from signedimp.cryptobase.md5 import md5

