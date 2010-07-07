"""

  signedimp.bootstrap:  minimal bootstrapping code for signed imports

This module contains the minimal code necessary to bootstrap the use of signed
imports.  It's carefully constructed not to perform any imports itself, save
modules known to be built into the interpreter or that are already loaded.

To get any real security out of this, you'll need to incorporate this script
wholesale into your main application script so that it runs before you try to
import anything.  Don't just import this script - after all, how would you 
verify the import of this module?  Use signedimp.get_bootstrap_code() to
obtain the necessary code.

"""


SIGNEDIMP_HASHFILE_NAME = "signedimp-manifest.txt"


class IntegrityCheckError(ValueError):
    """Error raised when integrity of a resource cannot be verified."""
    pass

class IntegrityCheckFailed(IntegrityCheckError):
    """Error raised when an integrity check is available, and fails."""
    pass

class IntegrityCheckMissing(IntegrityCheckError):
    """Error raised when an integrity check is not available."""
    pass



def _signedimp_mod_available(modname):
    """Check whether the named module is safely available.

    To be safe it must be either built into the interpreter, or be already
    loaded in sys.modules.
    """
    if modname in sys.builtin_module_names:
        return True
    if modname in sys.modules:
        return True
    return False


#  The sys module is always builtin, since it's needed to do imports.
import sys

#  Get the "imp" module so we can simulate the standard import machinery.
#  It must be builtin or this whole exercise is pointless.
if not _signedimp_mod_available("imp"):
    err = "'imp' module is not safely available, integrity checks impossible"
    raise IntegrityCheckMissing(err)
import imp


#  Get the "marshal" module so we can treat code objects as bytes.
#  It must be builtin or this whole exercise is pointless.
if not _signedimp_mod_available("marshal"):
    err = "'marshal' module is not safely available, " \
          "integrity checks impossible"
    raise IntegrityCheckMissing(err)
import marshal


#  Get a minimal simulation of the "os" module.
#  It must be builtin or this whole exercise is pointless.
def _signedimp_make_os_module():
    if _signedimp_mod_available("os") and _signedimp_mod_available("os.path"):
        import os
        return os
    if _signedimp_mod_avilable("posix"):
        from posix import stat
        SEP = "/"
    elif _signedimp_mod_avilable("nt"):
        from nt import stat
        SEP = "\\"
    else:
        err = "no os modules are safely available, integrity checks impossible"
        raise IntegrityCheckMissing(err)
    class os:
        class path:
            @staticmethod
            def join(*args):
                """Local re-implementation of os.path.join."""
                return SEP.join(args)
            @staticmethod
            def exists(path):
                """Local re-implementation of os.path.exists."""
                try:
                    stat(path)
                except EnvironmentError:
                    return False
                return True
    return os
os = _signedimp_make_os_module()


class SignedHashDatabase(object):
    """An in-memory database of verified hash data.

    This class is used to validate generic data blobs against a signed database
    of their expected hash values.
    """

    def __init__(self,valid_keys=[],hashdata=None):
        self.valid_keys = valid_keys
        self.hashes = {}
        if hashdara is not None:
            self.parse_hash_data(hashdata)

    def validate(self,typ,name,data):
        """Validate data of the given type against our hash database."""
        try:
            hashes = self.hashes[(typ,name)]
        except KeyError:
            raise IntegrityCheckMissing("no valid hash for "+name)
        for (htyp,hval) in hashes:
            if not self._check_hash(htyp,hval,data):
                raise IntegrityCheckFailed("invalid hash for "+fullname)

    def _check_hash(self,type,hash,data):
        if type == "md5":
            return _signedimp_md5(data) == hash
        if type == "sha1":
            return _signedimp_sha1(data) == hash
        raise ValueError("unknown hash type: %s" % (type,))

    def parse_hash_data(self,hashdata):
        """Load hash data from the given string.

        The format is a simple text file where the initial lines give a key
        fingerprint and signature, then there's a blank line and a hash type
        identifier, then each remaining line is a hash db entry.  Example:

          ----
          key1fingerprint signature1
          key2fingerprint signature2

          md5
          m 76f3f13442c26fd4f1c709c7b03c6b76 os
          m f56dbc5ee6774e857a7ef07accdbd19b hashlib
          d 43b74fc5d2acb6b4e417f4feff06dd81 some/data/file.txt
          ----

        """
        offset = 0
        signatures = []
        lines = hashdata.split("\n")
        #  Find all valid keys that have provided a signature.
        for ln in lines:
            offset += len(ln)
            ln = ln.strip()
            if not ln:
                break
            try:
                fingerprint,signature = ln.split()
                signature = _signedimp_b64decode(signature)
            except ValueError:
                return
            for k in self.valid_keys:
                if k.fingerprint() == fingerprint:
                    signatures.append((k,signature))
        if not signatures:
            return
        #  Check the signature for each key
        signeddata = hashdata[offset:]
        for (k,sig) in signatures:
            if not k.verify(signeddata,sig):
                err = "bad signature from " + fingerprint
                raise IntegrityCheckFailed(err)
        #  Next is the hash type identifier
        try:
            htyp = lines.next().strip()
        except StopIteration:
            return
        #  Now we can load each hash line
        for ln in lines:
            try:
                typ,hval,name = ln.strip().split(None,2)
            except ValueError:
                continue
            try:
                hashes = self.hashes[(typ,name)]
            except KeyError:
                self.hashes[(typ,name)] = hashes = []
            hashes.append((htyp,hval))



class SignedImportManager(object):
    """Meta-path import hook for managing signed imports.

    This is a PEP-302-compliant meta-path hook which wraps the standard import
    machinery so that all code is verified before it is loaded.

    To enable signature validation on your python imports, create an instance
    of this class with appropriate arguments, then call its "install" method.
    This will place the manager as the first entry on sys.meta_path.
    """

    def __init__(self,valid_keys=[]):
        self.valid_keys = [k for k in valid_keys]
        self.hashdb = SignedHashDatabase(self.valid_keys)

    def install(self):
        """Install this manager into the process import machinery."""
        if self not in sys.meta_path:
            sys.meta_path.insert(0,self)
        #  Try to speed things up by loading faster crypto primatives.
        for mod in ("signedimp.crypto",):
            try:
                loader = self.find_module(mod)
                if loader is not None:
                    loader.load_module(mod)
            except ImportError:
                pass
        _signedimp_make_cryptofuncs()

    def pretend_sign_directory(self,path):
        """Add valid hashes for each module found in the given dir.

        Good for testing purposes :-)
        """
        import os
        while path.endswith(os.sep):
            path = path[:-1]
        for (dirnm,subdirs,filenms) in os.walk(path):
            #  For non-root dirs, make sure they're a package before recursing.
            if dirnm != path:
                for (suffix,_,_) in imp.get_suffixes():
                    if os.path.exists(os.path.join(dirnm,"__init__"+suffix)):
                        break
                else:
                    del subdirs[:]
                    continue
            #  For every file, try to sign it as a module.
            for filenm in filenms:
                for (suffix,_,_) in imp.get_suffixes():
                    if filenm.endswith(suffix):
                        basenm = os.path.join(dirnm,filenm[:-1*len(suffix)])
                        break
                else:
                    continue
                #  We want to preferentially sign .py files over .pyc, and
                #  either over a c extension.  Fortunately this the order
                #  they're returned in by imp.get_suffixes().
                for (suffix,_,typ) in imp.get_suffixes():
                    if os.path.exists(basenm+suffix):
                        modpath = basenm + suffix
                        modname = basenm[len(path)+1:].replace(os.sep,".")
                        self.pretend_sign_module(modname,modpath,typ)
                        break


    def pretend_sign_module(self,modname,modpath,typ=None):
        if "m" not in self.hashdata:
            self.hashdata["m"] = {}
        if modname.endswith(".__init__"):
            modname = modname.rsplit(".",1)[0]
        if modname not in self.hashdata["m"]:
            if typ == imp.PY_SOURCE:
                mode = "rU"
            else:
                mode = "rb"
            with open(modpath,mode) as f:
                moddata = f.read()
            self.hashdata["m"][modname] = []
            modhash = _signedimp_md5(moddata)
            self.hashdata["m"][modname].append((_signedimp_md5,modhash))
                

    def find_module(self,fullname,path=None):
        """Get the loader for the given module.

        This method locates the loader that would ordinarily be used for the
        given module, and wraps it in a SingledLoader instance so that all
        data is validated immediately prior to being loaded.
        """
        loader = self._find_loader(fullname,path)
        return SignedLoader(self,loader)

    def _find_loader(self,fullname,path):
        """Find the loader that would normally be used for the given module.

        This basically emulates the standard lookup machinery, finding the
        loader that we need to interrogate for details on the given module.
        """
        found_me = False
        for mphook in sys.meta_path:
            if found_me:
                loader = mphook.find_module(fullname,path)
                if loader is not None:
                    return loader
            elif mphook is self:
                found_me = True
        for path in sys.path:
            importer = self._get_importer(path)
            loader = importer.find_module(fullname)
            if loader is not None:
                return loader
        raise ImportError(fullname)

    def _get_importer(self,path):
        """Get the importer for the given sys.path item.

        This emulates the standard handling of sys.path_hooks, with the added
        bonus of returning a DefaultImporter instance if no hook is found.
        """
        try:
            importer = sys.path_importer_cache[path]
        except KeyError:
            for importer_class in sys.path_hooks:
                try:
                    importer = importer_class(path)
                except ImportError:
                    pass
                else:
                    sys.path_importer_cache[path] = importer
                    break
            else:
                sys.path_importer_cache[path] = None
                importer = DefaultImporter(path)
        else:
            if importer is None:
                importer = DefaultImporter(path)
        return importer
        

class SignedLoader:
    """Wrapper class for managing signed imports from a specific loader.

    The SignedImportManager returns instances of this class to wrap whatever
    loader would ordinarily be used for a given module.  When requested to
    load a module or data file, this wrapper first checks its hash against
    the loaded database and errors out if it doesn't match.
    """

    def __init__(self,manager,loader):
        self.manager = manager
        self.loader = loader
        self.hashdb = SignedHashDatabase(manager.valid_keys)
        try:
            hashdata = self.loader.get_data(SIGNEDIMP_HASHFILE_NAME)
        except EnvironmentError:
            pass
        else:
            self.hashdb.parse_hash_data(hashdata)

    def load_module(self,fullname):
        """Load the specific module, checking its integrity first."""
        try:
            return sys.modules[fullname]
        except KeyError:
            pass
        if fullname not in sys.builtin_module_names:
            data = self._get_module_data(fullname)
            self.validate_module(fullname,data)
        return self.loader.load_module(fullname)

    def get_data(self,path):
        """Get the data from the given path, checking its integrity first."""
        data = self.loader.get_data(path)
        self.validate_data(path,data)
        return data

    def is_package(self,fullname):
        return self.loader.is_package(fullname)

    def get_code(self,fullname):
        return self.loader.get_code(fullname)

    def get_source(self,fullname):
        return self.loader.get_source(fullname)

    def get_filename(self,fullname):
        return self.loader.get_filename(fullname)

    def validate_module(self,fullname,data):
        """Validate the given module data against our signature database."""
        self._validate("m",fullname,data)

    def validate_data(self,path,data):
        """Validate the given extra data against our signature database."""
        self._validate("d",fullname,data)

    def _validate(self,typ,name,data):
        """Validate date for the given type specifier and name.

        This performs validate against the local database and the main manager
        database.  If it's not found in either location, IntegrityCheckMissing
        error is raised.
        """
        try:
            self.hashdb.validate(typ,name,data)
        except IntegrityCheckMissing:
            self.manager.hashdb.validate(typ,name,data)
        else:
            try:
                self.manager.hashdb.validate(typ,fname,data)
            except IntegrityCheckMissing:
                pass

    def _get_module_data(self,fullname):
        """Get the raw data for the given module.

        This is the data that must be included in a valid signature.  It's
        one of the following, searched for in order:

            * the raw data from the compiled bytecode file
            * the source code from the module source file
            * the raw data from the object file

        Note that this is a different order to the way imports are searched;
        we need to check the bytecode if it's present because that will be
        used in preference to the source.  If the module is found as both
        a bytecode file and an object file, an error is raised.

        This assumes that the loader has files laid out in the same scheme
        as the default import machinery, so we can convert a module name to
        a path and read the file using loader.get_data().
        """
        if self.loader.is_package(fullname):
            return self._get_module_data(fullname+".__init__")
        found_data = None
        found_types = []
        for codetype in (imp.PY_COMPILED,imp.PY_SOURCE,imp.C_EXTENSION):
            for (suffix,_,typ) in imp.get_suffixes():
                if typ != codetype:
                    continue
                for sep in ("/","\\"):
                    path = fullname.replace(".",sep) + suffix
                    try:
                        data = self.loader.get_data(fullpath)
                    except AttributeError:
                        err = "loader has no get_data method"
                        raise IntegrityCheckMissing(err)
                    except IOError:
                        pass
                    else:
                        if found_data is None:
                            found_data = data
                        found_types.append(typ)
        if len(found_types) > 1:
            if found_types != [imp.PY_COMPILED,imp.PY_SOURCE]:
                err = "duplicate code found for " + fullname
                raise IntegrityCheckFailed(err)
        return data



def DefaultImporter(path):
    """Importer emulating the standard import mechanism.

    This is a placeholder implementation for modules that are found via the
    standard builtin import mechanism.

    It's also not really a class, it's a factory function that uses a cache.
    The real class is called _DefaultImporter.
    """
    try:
        return DefaultImporter.importer_cache[path]
    except KeyError:
        DefaultImporter.importer_cache[path] = _DefaultImporter(path)
        return DefaultImporter.importer_cache[path]
DefaultImporter.importer_cache = {}


class _DefaultImporter:
    """Importer emulating the standard import mechanism.

    This is a placeholder implementation for modules that are found via the
    standard builtin import mechanism.
    """

    def __init__(self,path):
        self.path = path

    def _exists(self,path,*args):
        if path is None:
            path = [self.path]
        for p in path:
            if os.path.exists(os.path.join(p,*args)):
                return True
        return False

    def find_module(self,fullname,path=None):
        if fullname in sys.builtin_module_names:
            return self
        if "." not in fullname:
            modname = fullname
        else:
            pkgname,modname = fullname.rsplit(".",1)
            pkg = self.load_module(pkgname)
            path = pkg.__path__
        for (suffix,_,_) in imp.get_suffixes():
            if self._exists(path,modname+suffix):
                return self
            if self._exists(path,modname,"__init__"+suffix):
                return self
        return None

    def _get_module_info(self,fullname):
        if "." not in fullname:
            modname = fullname
            path = None
        else:
            pkgname,modname = fullname.rsplit(".",1)
            pkg = self.load_module(pkgname)
            path = pkg.__path__
        return imp.find_module(modname,path)

    def load_module(self,fullname):
        try:
            return sys.modules[fullname]
        except KeyError:
            mod = imp.new_module(fullname)
            mod.__file__ = "<loading>"
            mod.__loader__ = self
            mod.__path__ = []
            sys.modules[fullname] = mod
        file,pathname,description = self._get_module_info(fullname)
        try:
            if description[2] == imp.PKG_DIRECTORY:
                mod.__path__ = [pathname]
            mod = imp.load_module(fullname,file,pathname,description)
        finally:
            if file is not None:
                file.close()
        sys.modules[fullname] = mod
        return mod

    def is_package(self,fullname):
        file,pathname,description = self._get_module_info(fullname)
        file.close()
        return (description[2] == imp.PKG_DIRECTORY)

    def get_source(self,fullname):
        file,pathname,description = self._get_module_info(fullname)
        file.close()
        if description[2] == imp.PKG_DIRECTORY:
            for (suffix,_,typ) in imp.get_suffixes():
                if typ != imp.PY_SOURCE:
                    continue
                initfile = os.path.join(pathname,"__init__"+suffix)
                if os.path.exists(initfile):
                    f = open(initfile,"rU")
                    try:
                        return f.read()
                    finally:
                        f.close()
            return self.get_source(fullname+".__init__")
        else:
            pathbase = pathname[:-1*len(description[0])]
            for (suffix,_,typ) in imp.get_suffixes():
                if typ != imp.PY_SOURCE:
                    continue
                sourcefile = pathbase+suffix
                if os.path.exists(sourcefile):
                    f = open(sourcefile,"rU")
                    try:
                        return f.read()
                    finally:
                        f.close()
        return None

    def get_code(self,fullname):
        file,pathname,description = self._get_module_info(fullname)
        file.close()
        if description[2] == imp.PKG_DIRECTORY:
            for (suffix,_,typ) in imp.get_suffixes():
                if typ != imp.PY_COMPILED:
                    continue
                initfile = os.path.join(pathname,"__init__"+suffix)
                if os.path.exists(initfile):
                    f = open(initfile,"rb")
                    try:
                        f.seek(8)
                        return marshal.load(f)
                    finally:
                        f.close()
            return self.get_code(fullname+".__init__")
        else:
            pathbase = pathname[:-1*len(description[0])]
            for (suffix,_,typ) in imp.get_suffixes():
                if typ != imp.PY_COMPILED:
                    continue
                codefile = pathbase+suffix
                if os.path.exists(codefile):
                    f = open(codefile,"rb")
                    try:
                        f.seek(8)
                        return marshal.load(f)
                    finally:
                        f.close()
            source = self.get_source(fullname)
            if source is not None:
                return compile(source,pathname,"exec")
        return None

        
    def get_data(self,path):
        return open(os.path.join(self.path,path),"rb").read()


def _signedimp_make_cryptofuncs():
    """Make the best versions of hashfuncs we can manage.

    This attempts to replace the default pure-python hash functions with
    something faster, assuming such a module is available.
    """
    global _signedimp_md5
    global _signedimp_sha1
    global _signedimp_b64decode
    global RSAKeyWithPSS
    if _signedimp_mod_available("base64"):
        import base64
        def _signedimp_b64decode(data):
            return base64.b64decode(data)
    if _signedimp_mod_available("signedimp.crypto"):
        # Awesome, we can use our crypto primatives directly
        import signedimp.crypto.md5
        import signedimp.crypto.sha1
        import signedimp.crypto.rsa
        def _signedimp_md5(data):
            return signedimp.crypto.md5.md5(data).hexdigest()
        def _signedimp_sha1(data):
            return signedimp.crypto.sha1.sha1(data).hexdigest()
        RSAKeyWithPSS = signedimp.crypto.rsa.RSAKeyWithPSS
    elif _signedimp_mod_available("hashlib"):
        # Great, we can use hashlib directly
        import hashlib
        def _signedimp_md5(data):
            return hashlib.md5(data).hexdigest()
        def _signedimp_sha1(data):
            return hashlib.sha1(data).hexdigest()
    elif _signedimp_mod_available("_hashlib"):
        # Good, we can use the exposed openssl interface directly
        import _hashlib
        def _signedimp_md5(data):
            return _hashlib.openssl_md5(data).hexdigest()
        def _signedimp_sha1(data):
            return _hashlib.openssl_sha1(data).hexdigest()
    else:
        if _signedimp_mod_available("_md5"):
            #  OK, at least md5 is builtin
            import _md5
            def _signedimp_md5(data):
                return _md5.new(data).hexdigest()
        if _signedimp_mod_available("_sha"):
            #  OK, at least sha1 is builtin
            import _sha
            def _signedimp_sha1(data):
                return _sha.new(data).hexdigest()
        #  If all else fails, we've left them as pure-python implementations

_signedimp_md5type = None
def _signedimp_md5(data):
    """Pure-python implementation of md5 hash.

    This is horribly slow and probably broken, but it's the best we can do
    if hashlib is not available safely.  It uses the pure-python MD5 code
    from the PyPy project, which is avilable under the Python License.
    """
    global _signedimp_md5type
    if not _signedimp_md5type:
        from signedimp.cryptobase.md5 import MD5Type
        _signedimp_md5type = MD5Type
    hash = _signedimp_md5type()
    hash.update(data)
    return hash.hexdigest()

_signedimp_sha1type = None
def _signedimp_sha1(data):
    """Pure-python implementation of sha1 hash.

    This is horribly slow and probably broken, but it's the best we can do
    if hashlib is not available safely.  It uses the pure-python SHA1 code
    from the PyPy project, which is avilable under the Python License.
    """
    global _signedimp_sha1type
    if not _signedimp_sha1type:
        from signedimp.cryptobase.sha1 import sha1
        _signedimp_sha1type = sha1
    return _signedimp_sha1type(data).hexdigest()

_signedimp_RSAKeyWithPSS = None
def RSAKeyWithPSS(modulus,pub_exponent):
    """Pure-python implementation of RSA-PSS verification.

    This is horribly slow and probably broken, but it's the best we can do
    if PyCrypto is not available safely.
    """
    global _signedimp_RSAKeyWithPSS
    if not _signedimp_RSAKeyWithPSS:
        from signedimp.cryptobase.rsa import RSAKeyWithPSS
        _signedimp_RSAKeyWithPSS = RSAKeyWithPSS
    return _signedimp_RSAKeyWithPSS(modulus,pub_exponent)

_signedimp_make_cryptofuncs()


def _signedimp_b64unquad(quad):
    """Decode a single base64-encoded quad of bytes."""
    n = 0
    for c in quad:
        n = n << 6
        if "A" <= c <= "Z":
            n += ord(c) - 65
        elif "a" <= c <= "z":
            n += ord(c) - 71
        elif "0" <= c <= "9":
            n += ord(c) + 4
        elif c == "+":
            n += 62
        elif c == "/":
            n += 63
        else:
            raise ValueError
    bytes = []
    while n > 0:
        bytes.append(chr(n & 0x000000FF))
        bytes.append(chr((n & 0x0000FF00) >> 8))
        bytes.append(chr((n & 0x00FF0000) >> 16))
        bytes.append(chr((n & 0xFF000000) >> 24))
        n = n >> 32
    bytes = "".join(reversed(bytes))
    for i in xrange(len(bytes)):
        if bytes[i] != "\x00":
            return bytes[i:]


def _signedimp_b64decode(data):
    output = []
    if len(data) % 4 != 0:
        raise ValueError("b64 data must be multiple of 4 in length")
    for i in xrange(0,len(data),4):
        quad = data[i:i+4]
        if quad.endswith("=="):
            quad = quad[:2]+"AA"
            trim = 2
        elif quad.endswith("="):
            quad = quad[:3]+"A"
            trim = 1
        else:
            trim = 0
        if trim:
            output.append(_signedimp_b64unquad(quad)[:-1*trim])
        else:
            output.append(_signedimp_b64unquad(quad))
    return "".join(output)

