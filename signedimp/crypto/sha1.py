#  Copyright (c) 2009-2010, Cloud Matrix Pty. Ltd.
#  All rights reserved; available under the terms of the BSD License.
"""

  signedimp.crypto.sha1:  the SHA1 hashing alorithm, fast version.

"""

from __future__ import absolute_import

try:
    from hashlib import sha1
except ImportError:
    try:
        from Crypto.Hash import SHA
        sha1 = SHA.new
    except ImportError:
        from signedimp.cryptobase.sha1 import sha1


