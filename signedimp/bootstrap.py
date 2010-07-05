"""

  signedimp.bootstrap:  minimal bootstrapping code for signed imports

This module contains the minimal code necessary to bootstrap the use of signed
imports.  It's carefully constructed not to perform any imports itself, save
modules known to be built into the interpreter.

To get any real security out of this, you'll need to incorporate this script
wholesale into your main application script so that it runs before you try to
import anything.  Don't just import this script - after all, how would you 
verify the import of this module?

"""


SIGNEDIMP_HASHFILE_NAME = "signedimp-manifest"


class IntegrityCheckError(ValueError):
    """Error raised when integrity checks fail."""
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
    raise RuntimeError(err)
import imp
DYLIB_SUFFIXES = [suffix for (suffix,_,typ) in imp.get_suffixes() \
                         if typ == imp.C_EXTENSION]

#  Get the "math" module so we can implement pure-python has functions.
#  It must be builtin or this whole exercise is pointless.
if not _signedimp_mod_available("math"):
    err = "'math' module is not safely available, integrity checks impossible"
    raise RuntimeError(err)
import imp
DYLIB_SUFFIXES = [suffix for (suffix,_,typ) in imp.get_suffixes() \
                         if typ == imp.C_EXTENSION]

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
        raise RuntimeError(err)
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



class PublicKey:
    """Generic base class for verifying sigs with a public key."""

    def verify(self,data,signature):
        pass

    def fingerprint(self):
        return "XXX"

    def on_import_enabled(self):
        pass



class SignedImportManager:
    """Meta-path import hook for managing signed imports.

    This is a PEP-302-compliant meta-path hook which wraps the standard import
    machinery so that all code is verified before it is loaded.

    To enable signature validation on your python imports, create an instance
    of this class with appropriate arguments, then call its "install" method.
    This will place the manager as the first entry on sys.meta_path.
    """

    def __init__(self,valid_keys=[]):
        self.valid_keys = [k for k in valid_keys]
        self.hashdata = {}

    def install(self):
        """Install this manager into the process import machinery."""
        if self not in sys.meta_path:
            sys.meta_path.insert(0,self)
        for k in self.valid_keys:
            k.on_import_enabled()

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
        self.hashdata = {}
        hashfiles = [SIGNEDIMP_HASHFILE_NAME+".txt",]
        for key in self.manager.valid_keys:
            filenm = SIGNEDIMP_HASHFILE_NAME+"."+key.fingerprint()+".txt"
            hashfiles.append(filenm)
        for filenm in hashfiles:
            try:
                hashdata = self.loader.get_data(filenm)
            except EnvironmentError:
                pass
            else:
                self._load_hashdata(hashdata)

    def load_module(self,fullname):
        """Load the specific module, checking its integrity first."""
        try:
            return sys.modules[fullname]
        except KeyError:
            pass
        if fullname not in sys.builtin_module_names:
            # TODO: remove this hack
            if not  fullname.startswith("signedimp"):
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
        self._validate(fullname,"m",data)

    def validate_data(self,path,data):
        """Validate the given extra data against our signature database."""
        self._validate(fullname,"d",data)

    def _validate(self,fullname,typ,data):
        """Validate data of the given type against our signature database."""
        hashes = []
        try:
            hashes.extend(self.hashdata[typ][fullname])
        except KeyError:
            pass
        try:
            hashes.extend(self.manager.hashdata[typ][fullname])
        except KeyError:
            pass
        for (hasher,hashval) in hashes:
            if hasher(data) != hashval:
                raise IntegrityCheckError("invalid hash for "+fullname)
        if not hashes:
            raise IntegrityCheckError("no valid hash for "+fullname)

    def _load_hashdata(self,hashdata):
        """Load hash data from a signed file.

        The file is a simple text file where the first line is the fingerprint
        of the public key, the second is the signature for the rest of the
        data, the third is a hash type indicator and all other lines are of
        the form "typ hash name".
        """
        try:
            fingerprint,signature,data = hashdata.split("\n",2)
            fingerprint = fingerprint.strip()
            signature = signature.strip()
        except ValueError:
            return
        #  Validate the signature, choke if invalid.
        #  If the key is not known, ignore this data.
        for k in self.manager.valid_keys:
            if k.fingerprint() == fingerprint:
                k.verify(data,signature)
                break
        else:
            return
        #  Obtain a hasher callable
        try:
            hashtype,hashlines = data.split("\n",2)
            hashtype = hashtype.strip()
        except ValueError:
            return
        if hashtype == "md5":
            hasher = _signedimp_md5
        elif hashtype == "sha1":
            hasher = _signedimp_sha1
        else:
            return
        #  Now we can load each of the hash lines:
        for ln in hashlines.split("\n"):
            try:
                typ,hashval,name = ln.strip().split(None,2)
            except ValueError:
                continue
            if typ not in self.hashdata:
                self.hashdata[typ] = {}
            if name not in self.hashdata[typ]:
                self.hashdata[typ][name] = []
            self.hashdata[typ][name].append(hashval)

    def _get_module_data(self,fullname):
        """Get the raw data for the given module.

        This is the data that must be included in a valid signature.  It's
        the source if available, the bytecode if available, and the raw file
        data otherwise.
        """
        try:
            data = self.loader.get_source(fullname)
        except AttributeError:
            raise
            raise IntegrityCheckError("loader has no get_source method")
        except ImportError:
            pass
        else:
            if data is not None:
                return data
        try:
            data = self.loader.get_code(fullname)
        except AttributeError:
            raise IntegrityCheckError("loader has no get_code method")
        except ImportError:
            pass
        else:
            if data is not None:
                return data
        path = fullname.replace(".","/")
        for suffix in DYLIB_SUFFIXES:
            fullpath = path + suffix
            try:
                return self.loader.get_data(fullpath)
            except AttributeError:
                raise IntegrityCheckError("loader has no get_data method")
            except IOError:
                pass
        path = fullname.replace(".","\\")
        for suffix in DYLIB_SUFFIXES:
            fullpath = path + suffix
            try:
                return self.loader.get_data(fullpath)
            except AttributeError:
                raise IntegrityCheckError("loader has no get_data method")
            except IOError:
                pass
        raise IntegrityCheckError("could not get raw module data")



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

    def get_source(self,fullname):
        file,pathname,description = self._get_module_info(fullname)
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
        if description[2] != imp.PY_SOURCE:
            return None
        return file.read()

    def get_code(self,fullname):
        file,pathname,description = self._get_module_info(fullname)
        if description[2] == imp.PKG_DIRECTORY:
            for (suffix,_,typ) in imp.get_suffixes():
                if typ != imp.PY_COMPILED:
                    continue
                initfile = os.path.join(pathname,"__init__"+suffix)
                if os.path.exists(initfile):
                    f = open(initfile,"rb")
                    try:
                        return f.read()
                    finally:
                        f.close()
            return self.get_source(fullname+".__init__")
        if description[2] != imp.PY_COMPILED:
            return None
        return file.read()
        
    def get_data(self,path):
        return open(os.path.join(self.path,path),"rb").read()


def _signedimp_make_hashfuncs():
    """Make the best versions of hashfuncs we can manage.

    This attempts to replace the default pure-python hash functions with
    something faster, assuming such a module is available.
    """
    global _signedimp_md5
    global _signedimp_sha1
    if _signedimp_mod_available("hashlib"):
        # Awesome, we can use hashlib directly
        import hashlib
        def _signedimp_md5(data):
            return hashlib.md5(data).hexdigest()
        def _signedimp_sja1(data):
            return hashlib.sha1(data).hexdigest()
    elif _signedimp_mod_available("_hashlib"):
        # Awesome, we can use the exposed openssl interface directly
        import _hashlib
        def _signedimp_md5(data):
            return _hashlib.openssl_md5(data).hexdigest()
        def _signedimp_sha1(data):
            return _hashlib.openssl_sha1(data).hexdigest()
    else:
        #  Just leave them at their pure-python default implementations
        pass

_signedimp_md5type = None
def _signedimp_md5(data):
    """Pure-python implementation of md5 hash.

    This is horribly slow and probably broken, but it's the best we can do
    if hashlib is not available safely.  It uses the pure-python MD5 code
    from the PyPy project, which is avilable under the Python License.
    """
    global _signedimp_md5type
    if not _signedimp_md5type:
        from signedimp.purepy.md5 import MD5Type
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
        from signedimp.purepy.sha1 import sha
        _signedimp_sha1type = sha
    return _signedimp_sha1type(data).hexdigest()

_signedimp_make_hashfuncs()
