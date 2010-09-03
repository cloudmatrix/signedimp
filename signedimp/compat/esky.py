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

    rsakey_source = _getsrc(cryptobase.rsa,"    ")
    rsakey_source = rsakey_source.replace("import sys","")

    b64decode_source = _getsrc(bootstrap._signedimp_util.b64decode,"    ")
    b64unquad_source = _getsrc(bootstrap._signedimp_util._b64unquad,"    ")

    pubkey = key.get_public_key()
     
    return """


from pypy.rlib.rbigint import rbigint
from pypy.rlib.rmd5 import RMD5
from pypy.rlib.rsha import RSHA

def md5(self,data=""):
    h = RMD5()
    h.update(data)
    return h

def sha1(self,data=""):
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
    %(rsakey_source)s
    class _signedimp_util:
%(b64unquad_source)s
%(b64decode_source)s
        sha1 = staticmethod(sha1)
        md5 = staticmethod(md5)
        def profile_call(self,func):
            return func
    _signedimp_util = _signedimp_util()
%(signedhashdb_source)s
    key = %(pubkey)r
    key.modulus = rbigint.fromlong(key.modulus)
    key.pub_exponent = rbigint.fromlong(key.pub_exponent)
    def _bigint_pow(a,b,m=None):
        assert isinstance(a,rbigint)
        return a.pow(b,m)
    RSAKey._math.pow = staticmethod(_bigint_pow)
    def readfile(pathnm):
        fh = os_open(pathnm,0,0)
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

