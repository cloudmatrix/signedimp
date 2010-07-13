#  Copyright (c) 2009-2010, Cloud Matrix Pty. Ltd.
#  All rights reserved; available under the terms of the BSD License.
"""

  signedimp.bootstrap:  minimal bootstrapping code for signed imports

This module contains the minimal code necessary to bootstrap the use of signed
imports.  It's carefully constructed not to perform any imports itself, save
modules known to be built into the interpreter or that are already loaded.
It's also carefully constructed so that it can be incorporated directly
into other code with a minimum of fuss.

To get any real security out of this, you'll need to incorporate this script
wholesale into your main application script so that it runs before you try to
import anything.  Don't just import this script - after all, how would you 
verify the import of this module?  Use signedimp.tools.get_bootstrap_code() to
obtain the necessary code.

"""


__all__ = ["HASHFILE_NAME","IntegrityCheckError",
           "IntegrityCheckFailed","IntegrityCheckMissing",
           "SignedImportManager","RSAKeyWithPSS"]


#  Careful now, we can't just import things willy-nilly.  The following
#  tries to grab the things we absolutely need without polluting the
#  global namespace.

def _signedimp_mod_available(modname):
    """Check whether the named module is safely available.

    To be safe it must be either built into the interpreter, or already
    loaded in sys.modules.
    """
    if modname in sys.builtin_module_names:
        return True
    if sys.modules.get(modname) is not None:
        return True
    if imp.is_frozen(modname):
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
    if _signedimp_mod_available("posix"):
        from posix import stat
        SEP = "/"
    elif _signedimp_mod_available("nt"):
        from nt import stat
        SEP = "\\"
    else:
        err = "no os modules are safely available, integrity checks impossible"
        raise IntegrityCheckMissing(err)
    class os:
        sep = SEP
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


HASHFILE_NAME = "signedimp-manifest.txt"


class IntegrityCheckError(Exception):
    """Error raised when integrity of a resource cannot be verified."""
    pass

class IntegrityCheckFailed(IntegrityCheckError):
    """Error raised when an integrity check is available, and fails."""
    pass

class IntegrityCheckMissing(IntegrityCheckError):
    """Error raised when an integrity check is not available."""
    pass


class _signedimp_util:
    """Namespace containing utility functions that won't be exported.

    This namespace contains pure-python versions of some utility functions 
    that we need for this module.  Ordinarily you would use native versions
    of these functions, but that might require importing modules that can't
    be safely accessed during bootstrapping.  We need the pure-python versions
    as a last resort.
    """

    _md5type = None
    @staticmethod
    def md5(data=None):
        """Pure-python implementation of md5 hash.

        This is horribly slow and probably broken, but it's the best we can do
        if hashlib is not available safely.  It uses the pure-python MD5 code
        from the PyPy project, which is available under the Python License.
        """
        if not _signedimp_util._md5type:
            from signedimp.cryptobase.md5 import MD5Type
            _signedimp_util._md5type = MD5Type
        return _signedimp_util._md5type(data)

    _sha1type = None
    @staticmethod
    def sha1(data):
        """Pure-python implementation of sha1 hash.

        This is horribly slow and probably broken, but it's the best we can do
        if hashlib is not available safely.  It uses the pure-python SHA1 code
        from the PyPy project, which is available under the Python License.
        """
        if not _signedimp_util._sha1type:
            from signedimp.cryptobase.sha1 import sha1
            _signedimp_util._sha1type = sha1
        return _signedimp_util._sha1type(data)

    _RSAKeyWithPSS = None
    @staticmethod
    def RSAKeyWithPSS(modulus,pubexp,privexp=None):
        """Pure-python implementation of RSA-PSS verification.

        This is horribly slow and probably broken, but it's the best we can do
        if PyCrypto is not available safely.
        """
        if not _signedimp_util._RSAKeyWithPSS:
            from signedimp.cryptobase.rsa import RSAKeyWithPSS
            _signedimp_util._RSAKeyWithPSS = RSAKeyWithPSS
        return _signedimp_util._RSAKeyWithPSS(modulus,pubexp,privexp)

    @staticmethod
    def _b64unquad(quad):
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
        while len(bytes) < 3:
            bytes.append("\x00")
        bytes = "".join(reversed(bytes))
        return bytes[-3:]

    @staticmethod
    def b64decode(data):
        """Pure-python base-64 decoder.

        This is just awful and should only be used when the base64 module
        is not available.
        """
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
                output.append(_signedimp_util._b64unquad(quad)[:-1*trim])
            else:
                output.append(_signedimp_util._b64unquad(quad))
        return "".join(output)

    @staticmethod
    def recreate():
        """Try to make the best versions of the utility funcs we can.

        This method should be called whenever a new set of imports become
        available.  It will interrogate the runtime environment and try to
        find better implementations of the utility functions defined on
        this class.
        """
        if _signedimp_mod_available("base64"):
            try:
                import base64
                _signedimp_util.b64decode = staticmethod(base64.b64decode)
            except ImportError:
                pass
        if _signedimp_mod_available("signedimp.crypto"):
            # Awesome, we can use our crypto primitives directly
            try:
                import signedimp.crypto.md5
                import signedimp.crypto.sha1
                import signedimp.crypto.rsa
                _signedimp_util.md5 = md5.md5
                _signedimp_util.sha1 = sha1.sha1
                _signedimp_util.RSAKeyWithPSS = rsa.RSAKeyWithPSS
            except ImportError:
                pass
        elif _signedimp_mod_available("hashlib"):
            # Great, we can use hashlib directly
            try:
                import hashlib
                _signedimp_util.md5 = hashlib.md5
                _signedimp_util.sha1 = hashlib.sha1
            except ImportError:
                pass
        elif _signedimp_mod_available("_hashlib"):
            # Good, we can use the exposed openssl interface directly
            try:
                import _hashlib
                _signedimp_util.md5 = _hashlib.openssl_md5
                _signedimp_util.sha1 = _hashlib.openssl_sha1
            except (ImportError,AttributeError):
                pass
        else:
            if _signedimp_mod_available("_md5"):
                #  OK, at least md5 is builtin
                import _md5
                _signedimp_util.md5 = _md5.new
            if _signedimp_mod_available("_sha"):
                #  OK, at least sha1 is builtin
                import _sha
                _signedimp_util.sha1 = _sha.new
        #  If all else fails, we've left them as pure-python implementations


# We might be lucky and have some modules availabe...
_signedimp_util.recreate()


class SignedHashDatabase(object):
    """An in-memory database of verified hash data.

    This class is used to verify generic data blobs against a signed database
    of their expected hash values.  It encapsulates the file-parsing and
    verification logic shared by SignedImportManager and SignedLoader.
    """

    def __init__(self,valid_keys=[],hashdata=None):
        self.valid_keys = valid_keys
        self.hashes = {}
        if hashdata is not None:
            self.parse_hash_data(hashdata)

    def verify(self,typ,name,data):
        """Verify data of the given type against our hash database."""
        try:
            hashes = self.hashes[(typ,name)]
        except KeyError:
            raise IntegrityCheckMissing("no valid hash for "+name)
        for (htyp,hval) in hashes:
            if not self._check_hash(htyp,hval,data):
                raise IntegrityCheckFailed("invalid hash for "+name)

    def _check_hash(self,type,hash,data):
        """Check whether the hash of the given data matches the one given."""
        if type == "sha1":
            return _signedimp_util.sha1(data).hexdigest() == hash
        if type == "md5":
            return _signedimp_util.md5(data).hexdigest() == hash
        raise ValueError("unknown hash type: %s" % (type,))

    def parse_hash_data(self,hashdata):
        """Load hash data from the given string.

        The format is a simple text blob where the initial lines give key
        fingerprints and signatures, then there's a blank line and a hash type
        identifier, then each remaining line is a hash db entry.  Example:

          ----
          key1fingerprint base64-signature1
          key2fingerprint base64-signature2

          md5
          m 76f3f13442c26fd4f1c709c7b03c6b76 os
          m f56dbc5ee6774e857a7ef07accdbd19b hashlib
          d 43b74fc5d2acb6b4e417f4feff06dd81 some/data/file.txt
          ----

        """
        offset = 0
        signatures = []
        lines = iter(hashdata.split("\n"))
        #  Find all valid keys that have provided a signature.
        for ln in lines:
            offset += len(ln)+1
            ln = ln.strip()
            if not ln:
                break
            try:
                fingerprint,signature = ln.split()
                signature = _signedimp_util.b64decode(signature)
            except ValueError, e:
                return
            for k in self.valid_keys:
                if k.fingerprint() == fingerprint:
                    signatures.append((k,signature))
        #  If there weren't any usable signatures, we can't use this data.
        if not signatures:
            return
        #  Check the signature for each key
        signeddata = hashdata[offset:]
        for (k,sig) in signatures:
            if not k.verify(signeddata,sig):
                err = "bad signature from " + fingerprint
                raise IntegrityCheckFailed(err)
        #  Next line is the hash type identifier
        try:
            htyp = lines.next().strip()
        except StopIteration:
            return
        #  Now we can load each hash line into the database
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

    To enable signature verification on your python imports, create an instance
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
        #  Try to speed things up by loading faster crypto primitives.
        for mod in ("signedimp.crypto",):
            try:
                loader = self.find_module(mod)
                if loader is not None:
                    loader.load_module(mod)
            except (ImportError,IntegrityCheckMissing,):
                pass
        _signedimp_util.recreate()

    def find_module(self,fullname,path=None):
        """Get the loader for the given module.

        This method locates the loader that would ordinarily be used for the
        given module, and wraps it in a SignedLoader instance so that all
        data is verified immediately prior to being loaded.
        """
        loader = self._find_loader(fullname,path)
        return SignedLoader(self,loader)

    def _find_loader(self,fullname,path):
        """Find the loader that would normally be used for the given module.

        This basically emulates the standard lookup machinery defined by PEP
        302 to find the loader that we need to interrogate for details on the
        given module.
        """
        if path is None:
            loader = BuiltinImporter.find_module(fullname)
            if loader is not None:
                return loader
            path = sys.path
        found_me = False
        for mphook in sys.meta_path:
            if found_me:
                loader = mphook.find_module(fullname,path)
                if loader is not None:
                    return loader
            elif mphook is self:
                found_me = True
        for pathitem in path:
            importer = self._get_importer(pathitem)
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
    the loaded database and errors out if it doesn't match or is not present.
    """

    def __init__(self,manager,loader):
        self.manager = manager
        self.loader = loader
        self.hashdb = SignedHashDatabase(manager.valid_keys)
        try:
            hashdata = self.loader.get_data(HASHFILE_NAME)
        except (AttributeError,EnvironmentError):
            pass
        else:
            self.hashdb.parse_hash_data(hashdata)

    def __getattr__(self,attr):
        """Pass through simple attributes of the wrapped loader.

        This allows access to e.g. the "archive" and "prefix" attributes of
        a wrapper zipimporter object, while doing (moderately) careful not
        to allow calling its methods directly.
        """
        try:
            value = self.loader.__dict__[attr]
        except (KeyError,AttributeError):
            raise AttributeError(attr)
        else:
            if not isinstance(value,(int,long,basestring,float)):
                raise AttributeError(attr)
            return value

    def load_module(self,fullname,verify=True):
        """Load the specified module, checking its integrity first.

        This method is really key to the whole apparatus - it requests the
        raw module data from the loader object, verifies it against the
        hash database, and only if it's valid does it request that the loader
        actually import the module.

        If you really want to load non-verified code, you can pass the kwd arg
        "verify" as False.  But seriously, why would you want to do that?
        """
        try:
            return sys.modules[fullname]
        except KeyError:
            pass
        if verify and self.loader is not BuiltinImporter:
            data = self._get_module_data(fullname)
            if self.is_package(fullname):
                valname = fullname + ".__init__"
            else:
                valname = fullname
            self.verify_module(valname,data)
        mod = self.loader.load_module(fullname)
        mod.__loader__ = self
        return mod

    def get_data(self,path):
        """Get the data from the given path, checking its integrity first."""
        data = self.loader.get_data(path)
        self.verify_data(path,data)
        return data

    def is_package(self,fullname):
        """Check whether the given module is a package."""
        return self.loader.is_package(fullname)

    def get_code(self,fullname):
        """Get the code object for the given module.

        If you *really* needed to circumvent the checking of signed imports,
        you could use this method to get the module code object and create
        the module yourself.  But seriously, why would you do that?
        """
        return self.loader.get_code(fullname)

    def get_source(self,fullname):
        """Get the code object for the given module.

        If you *really* needed to circumvent the checking of signed imports,
        you could use this method to get the module source code, compile it and
        create the module yourself.  But seriously, why would you do that?
        """
        return self.loader.get_source(fullname)

    def get_filename(self,fullname):
        """Get the filename associated with the given module."""
        return self.loader.get_filename(fullname)

    def verify_module(self,fullname,data):
        """Verify the given module data against our signature database."""
        self._verify("m",fullname,data)

    def verify_data(self,path,data):
        """Verify the given extra data against our signature database."""
        self._verify("d",fullname,data)

    def _verify(self,typ,name,data):
        """Verify date for the given type specifier and name.

        This performs verification against the local database and the main
        manager database.  If a valid hash for the item is not found in
        either location, IntegrityCheckMissing error is raised.
        """
        try:
            self.hashdb.verify(typ,name,data)
        except IntegrityCheckMissing:
            self.manager.hashdb.verify(typ,name,data)
        else:
            try:
                self.manager.hashdb.verify(typ,name,data)
            except IntegrityCheckMissing:
                pass

    def _get_module_data(self,fullname):
        """Get the raw data for the given module.

        This is the data that must be included in a valid signature.  It's
        a concatentation of any of the following that are found, searched for
        in order:

            * the source code from the module source file
            * the raw data from the compiled bytecode file
            * the raw data from the object file

        This assumes that the loader has files laid out in the same scheme
        as the default import machinery, so we can convert a module name to
        a path and read the file using loader.get_data().
        """
        if self.is_package(fullname):
            fullname = fullname + ".__init__"
        data = []
        for (suffix,_,_) in imp.get_suffixes():
            for sep in ("/","\\"):
                path = fullname.replace(".",sep) + suffix
                try:
                    new_data = self.loader.get_data(path)
                except AttributeError:
                    err = "loader has no get_data method"
                    raise IntegrityCheckMissing(err)
                except IOError:
                    pass
                else:
                    data.append(new_data)
                    break
        return "\x00".join(data)



class BuiltinImporter(object):
    """Importer managing builtin and frozen modules.

    This is a singleton class managing the import of builtin and frozen
    modules.  It's the only loader that is implicitly trusted, since its
    modules come directly from the main executable.
    """

    @classmethod
    def find_module(self,fullname):
        if imp.is_builtin(fullname):
            return self
        if imp.is_frozen(fullname):
            return self
        return None

    @classmethod
    def load_module(self,fullname):
        try:
            return sys.modules[fullname]
        except KeyError:
            pass
        if imp.is_builtin(fullname):
            mod = imp.init_builtin(fullname)
        elif imp.is_frozen(fullname):
            mod = imp.init_frozen(fullname)
        else:
            raise ImportError(fullname + " is not builtin or frozen")
        sys.modules[fullname] = mod
        return mod

    @classmethod
    def is_package(self,fullname):
        if imp.is_builtin(fullname+".__init__"):
            return True
        if imp.is_frozen(fullname+".__init__"):
            return True
        return False



def DefaultImporter(path=None):
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

    def __init__(self,path=None,base_path=None):
        self.path = path
        if path is None:
            self.base_path = None
        elif base_path is None:
            #  If base_path is not given, find the best match on sys.path
            candidates = []
            for p in sys.path:
                #  Break early if we're an item directly on sys.path
                if p == path:
                    self.base_path = path
                    break
                #  Add it as a candidate if our path starts with that path
                if not p.endswith(os.sep):
                    p = p + os.sep
                if path.startswith(p):
                    candidates.append(p)
            else:
                if candidates:
                    #  Pick the longest prefix as our base_path
                    candidates.sort(key=len)
                    self.base_path = candidates[-1]
                else:
                    # We're nowhere on sys.path
                    self.base_path = path

    def _exists(self,*args):
        """Shortcut for checking if a file exists relative to my path."""
        return os.path.exists(os.path.join(self.path,*args))

    def _get_module_info(self,fullname):
        """Get the module info tuple for the given module.

        This is the tuple returned by imp.find_module(), but we have some
        extra logic to correctly handle dotted module names.
        """
        #  Since we're always created by a meta-path hook, we will always
        #  be given an entry from the package's __path__ if asked to load
        #  a sub-module.  No need to grab __path__ ourselves.
        modname = fullname.rsplit(".",1)[-1]
        if self.path is None:
            path = None
        else:
            path = [self.path]
        return imp.find_module(modname,path)

    def find_module(self,fullname,path=None):
        """Find a loader for the given module.

        If the module can be located, this method will always return self.
        """
        #  Since we're always created by a meta-path hook, we will always
        #  be given an entry from the package's __path__ if asked to load
        #  a sub-module.  No need to grab __path__ ourselves.
        modname = fullname.rsplit(".",1)[-1]
        for (suffix,_,_) in imp.get_suffixes():
            if self._exists(modname+suffix):
                return self
            if self._exists(modname,"__init__"+suffix):
                return self
        return None

    def load_module(self,fullname):
        """Load the given module."""
        try:
            return sys.modules[fullname]
        except KeyError:
            mod = imp.new_module(fullname)
            mod.__file__ = "<loading>"
            mod.__loader__ = self
            mod.__path__ = []
            sys.modules[fullname] = mod
        try:
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
        except ImportError:
            sys.modules.pop(fullname,None)
            raise

    def is_package(self,fullname):
        """Check if the given module is a package."""
        file,pathname,description = self._get_module_info(fullname)
        if file is not None:
            file.close()
        return (description[2] == imp.PKG_DIRECTORY)

    def get_source(self,fullname):
        """Get the source code for the given module."""
        file,pathname,description = self._get_module_info(fullname)
        if file is not None:
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
        """Get the code object for the given module."""
        file,pathname,description = self._get_module_info(fullname)
        if file is not None:
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
        """Get the specified data file.

        If a relative path is given, it is treated as relative to base_path
        rather than path.  This is mostly so it will correctly find the 
        hash database file.
        """
        if self.base_path is None:
            raise OSError
        return open(os.path.join(self.base_path,path),"rb").read()



def RSAKeyWithPSS(*args,**kwds):
    return _signedimp_util.RSAKeyWithPSS(*args,**kwds)

