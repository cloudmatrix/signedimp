"""

  signedimp.compat.esky:  esky integration support code for signedimp

This module contains support for using signedimp together with the "esky"
auto-update module.  Use the "get_bootstrap_code" function to get code for
a custom chainloading function, which will verify the chainloaded exe before
executing it.  This code should be passed in to bdist_esky as part of the
"bootstrap_code" option.

"""

import signedimp
from signedimp import bootstrap, tools, cryptobase
from signedimp.tools import _get_source_lines

def get_bootstrap_code(key,rpython=False):
    if rpython:
        return _get_bootstrap_code_rpython(key)
    signedimp_bootstrap = tools.get_bootstrap_code(indent="    ")
    pubkey = key.get_public_key()
    return """
def _make_signedimp_verify(orig_verify):
    %(signedimp_bootstrap)s
    key = signedimp.%(pubkey)r
    manager = signedimp.SignedImportManager([key])
    manager.install()
    def verify(target_file):
        orig_verify(target_file)
        manager._verify_file(target_file)
    return verify
verify = _make_signedimp_verify(verify)
""" % locals()


def _getsrc(obj,indent):
    return "\n".join(_get_source_lines(obj,indent,inline_crypto=False))

def _get_bootstrap_code_rpython(key):

    hashfile_name = signedimp.HASHFILE_NAME

    signedhashdb_source = _getsrc(bootstrap.SignedHashDatabase,"    ")
    signedhashdb_source = signedhashdb_source.replace("os.path.","")
    signedhashdb_source = signedhashdb_source.replace("os.sep","SEP")
    signedhashdb_source = signedhashdb_source.replace("import sys","")

    pss_source = _getsrc(cryptobase.pss,"    ")
    pss_source = pss_source.replace("import sys","")

    rsakey_source = _getsrc(cryptobase.rsa,"    ")
    rsakey_source = rsakey_source.replace("import sys","")

    b64decode_source = _getsrc(bootstrap._signedimp_util.b64decode,"    ")
    b64unquad_source = _getsrc(bootstrap._signedimp_util._b64unquad,"    ")

    pubkey = key.get_public_key()

    import os
    import sys
    if sys.platform == "win32":
        O_BINARY = os.O_BINARY
    else:
        O_BINARY = 0
     
    return """


from pypy.rlib.rbigint import rbigint
from pypy.rlib.rmd5 import RMD5
from pypy.rlib.rsha import RSHA

global md5
global sha1

def md5(data=""):
    h = RMD5()
    h.update(data)
    return h

def sha1(data=""):
    h = RSHA()
    h.update(data)
    return h

def _make_signedimp_verify(orig_verify):
    class IntegrityCheckError(Exception):
        pass
    class IntegrityCheckMissing(IntegrityCheckError):
        pass
    class IntegrityCheckFailed(IntegrityCheckError):
        pass
    HASHFILE_NAME = %(hashfile_name)r

    %(pss_source)s
    def zip(s1,s2):
        assert len(s1) == len(s2)
        pairs = []
        for i in xrange(len(s1)):
            pairs.append((s1[i],s2[i]))
        return pairs
    def make_mgf1(hash):
        def mgf1(mgfSeed,maskLen):
            assert maskLen > 0
            hLen = len(hash().digest())
            T = ""
            for counter in range(int(math.ceil(maskLen / (hLen*1.0)))):
                C = chr(counter)#math.long_to_bytes(counter)
                C = ('\\x00'*(4 - len(C))) + C
                assert len(C) == 4, "counter was too big"
                T += hash(mgfSeed + C).digest()
            assert len(T) >= maskLen, "generated mask was too short"
            return T[:maskLen]
        return mgf1
    MGF1_SHA1 = make_mgf1(sha1)

    %(rsakey_source)s

    class _signedimp_util:
%(b64unquad_source)s
%(b64decode_source)s
        def sha1(self,data=""):
            return sha1(data)
        def md5(self,data=""):
            return md5(data)
        def profile_call(self,func):
            return func
    _signedimp_util = _signedimp_util()

%(signedhashdb_source)s

    key = %(pubkey)r
    key.fingerprint()
    key.modulus = rbigint.fromlong(key.modulus)
    key.pub_exponent = rbigint.fromlong(key.pub_exponent)
    def _bigint_pow(a,b,m=None):
        assert isinstance(a,rbigint)
        return a.pow(b,m)
    def _bigint_long_to_bytes(n):
        rbytes = ""
        zero = rbigint(sign=1)
        while n.gt(zero):
            rbytes +=chr(n.and_(rbigint.fromint(0x000000FF)).toint())
            rbytes +=chr(n.rshift(8).and_(rbigint.fromint(0x0000FF)).toint())
            rbytes +=chr(n.rshift(16).and_(rbigint.fromint(0x00FF)).toint())
            rbytes +=chr(n.rshift(24).and_(rbigint.fromint(0xFF)).toint())
            n = n.rshift(32)
        i = len(rbytes) - 1
        while i > 0 and rbytes[i] == "\\x00":
            i -= 1
        bytes = ""
        for j in xrange(i+1):
            bytes += rbytes[i-j]
        return bytes
    def _bigint_bytes_to_long(bytes):
        n = rbigint(sign=1)
        for b in bytes:
            n = (n.lshift(8)).add(rbigint(digits=[ord(b)],sign=1))
        return n
    RSAKey._math.pow = staticmethod(_bigint_pow)
    RSAKey._math.long_to_bytes = staticmethod(_bigint_long_to_bytes)
    RSAKey._math.bytes_to_long = staticmethod(_bigint_bytes_to_long)

    def readfile(pathnm):
        fh = os_open(pathnm,%(O_BINARY)d,0)
        try:
            data = ""
            new_data = os_read(fh,1024*64)
            while new_data:
                data += new_data
                new_data = os_read(fh,1024*64)
            return data
        finally:
            os_close(fh)

    _hashdbs = {}
    def _load_hashdb(path):
        path = dirname(path)
        while True:
            hashfile = pathjoin(path,HASHFILE_NAME)
            if hashfile in _hashdbs:
                return path,_hashdbs[hashfile]
            if exists(hashfile):
                hashdata = readfile(hashfile)
                root_path = dirname(hashfile)
                hashdb = SignedHashDatabase([key],root_path=root_path)
                hashdb.parse_hash_data(hashdata)
                _hashdbs[hashfile] = hashdb
                return path,hashdb
            new_path = dirname(path)
            if path == new_path:
                break
        raise IntegrityCheckMissing(path)

    def verify(target_file):
        orig_verify(target_file)
        rootpath,hashdb = _load_hashdb(target_file)
        hashdb.verify(target_file[len(rootpath)+1:],readfile(target_file))
    return verify

verify = _make_signedimp_verify(verify)
""" % locals()

