"""

  signedimp.crypto.sha1:  the SHA1 hashing alorithm, fast version.

"""

try:
    from hashlib import sha1
except ImportError:
    try:
        from Crypto.Hash import SHA
        sha1 = SHA.new
    except ImportError:
        from signedimp.cryptobase.sha1 import sha1


