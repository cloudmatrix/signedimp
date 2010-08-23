#  Copyright (c) 2009-2010, Cloud Matrix Pty. Ltd.
#  All rights reserved; available under the terms of the BSD License.
"""

  signedimp.crypto.md5:  the MD5 hashing alorithm, fast version.

"""

from __future__ import absolute_import

try:
    from hashlib import md5
except ImportError:
    try:
        from Crypto.Hash import MD5
        md5 = MD5.new
    except ImportError:
        from signedimp.cryptobase.md5 import md5

