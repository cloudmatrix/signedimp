#  Copyright (c) 2009-2010, Cloud Matrix Pty. Ltd.
#  All rights reserved; available under the terms of the BSD License.
"""

  signedimp.tools:  tools for manipulating signed import datafiles


This module provides some high-level utility functions for generating the
signed module manifests required by signedimp.  For the common case of signing
a frozen application, you can use one of the following::

   sign_py2exe_app(appdirpath,key)

   sign_py2app_bundle(bundlepath,key)

   sign_cxfreeze_app(appdirpath,key)


To sign independently-distributed python modules, use one of the following::

   sign_directory(dirpath,key)

   sign_zipfile(zippath,key)

"""

from __future__ import with_statement
from __future__ import absolute_import

import os
import sys
import imp
import base64
import zipfile
import marshal
import struct
import inspect
import time
import subprocess

import signedimp
from signedimp.crypto.sha1 import sha1
from signedimp.crypto.md5 import md5
from signedimp.crypto.rsa import RSAKeyWithPSS

if sys.platform == "win32":
    from signedimp import winres


def get_bootstrap_code(indent=""):
    """Get sourcecode you can use for inline bootstrapping of signed imports.

    This function returns code that, when executed, creates the signedimp
    module and adds it to the local namespace as "signedimp". For most purposes 
    executing this code should be equivalent to doing "import signedimp".

    You would use it to boostrap signed imports in the startup script of your
    application, e.g. build a script like the following and hand it off to
    py2exe for freezing:

       SCRIPT = '''
       %s
       key = signedimp.RSAKeyWithPSS(modulus,pub_exponent)
       signedimp.SignedImportManager([key]).install()
       actually_start_my_appliction()
       ''' % (signedimp.tools.get_bootstrap_code(),)

    """
    def _get_source_lines(mod,indent):
        mod = __import__(mod,fromlist=["*"])
        src = inspect.getsource(mod)
        for ln in src.split("\n"):
            if ln.strip().startswith("from signedimp.cryptobase."):
                lnstart = ln.find("from")
                newindent = indent + ln[:lnstart]
                newmod = ln.strip()[5:].split()[0]
                for newln in _get_source_lines(newmod,newindent):
                    yield newln
            else:
                yield indent + ln
    return """
%(indent)ssignedimp = sys.modules.get("signedimp",None)
%(indent)sif signedimp is None:
%(indent)s    assert "imp" in sys.builtin_module_names
%(indent)s    def _signedimp_init():
%(indent)s        import imp
%(indent)s        signedimp = imp.new_module("signedimp")
%(indent)s        %(bscode)s
%(indent)s        lvars = locals()
%(indent)s        for nm in __all__:
%(indent)s            setattr(signedimp,nm,lvars[nm])
%(indent)s        signedimp.__package__ == "signedimp"
%(indent)s        signedimp.__path__ = []
%(indent)s        signedimp._path_is_broken = True
%(indent)s        return signedimp
%(indent)s    signedimp = sys.modules["signedimp"] = _signedimp_init()
""" % dict(bscode="\n".join(_get_source_lines("signedimp.bootstrap"," "*8)),
           indent=indent)


def sign_directory(path,key,hash="sha1",outfile=signedimp.HASHFILE_NAME):
    """Sign all the modules found in the given directory.

    This function walks the given directory looking for python modules, and
    signs everything it finds in that directory using the given key.

    By default the signed hash file is written into the root of the directory;
    redirect output by passing a filename or file object as 'outfile'.
    """
    outfile_was_string = isinstance(outfile,basestring)
    other_sigs = []
    #  Careful not to inlude the outfile itself in the signature.
    def files():
        for (dirnm,_,filenms) in os.walk(path):
            for filenm in filenms:
                if outfile_was_string:
                    if dirnm == path and filenm == outfile:
                        continue
                yield os.path.join(dirnm,filenm)
    hashdata = hash_files(path,files(),hash=hash)
    sig = key.sign(hashdata)
    sig = base64.b64encode(sig)
    #  If the file already exists, try to add our signature to it.
    #  If the data has changed, the old data is silently thrown away.
    if outfile_was_string:
        outfile = os.path.join(path,outfile)
        if os.path.exists(outfile):
            with open(outfile,"rb") as f:
                offset = 0
                for ln in f:
                    offset += len(ln)
                    if not ln.strip():
                        break
                    other_sigs.append(ln)
                f.seek(offset)
                olddata = f.read()
            if olddata != hashdata:
                other_sigs = []
        outfile = open(outfile,"wb")
    #  Write out the new hash data with prepended signature.
    try:
        outfile.write(key.fingerprint() + " " + sig + "\n")
        for sig2 in other_sigs:
            outfile.write(sig2)
        outfile.write("\n")
        outfile.write(hashdata)
    finally:
        if outfile_was_string:
            outfile.close()


def sign_zipfile(file,key,hash="sha1",outfile=signedimp.HASHFILE_NAME):
    """Sign all the modules found in the given zipfile.

    This function walks the given zipfile looking for python modules, and
    signs everything it finds in that file using the given key.  If the named
    file is not a zipfile, the function returns immediately and leaves the
    file unchanged.

    By default the signed hash file is written into the root of the zipfile;
    redirect output by passing a filename or file object as 'outfile'.
    """
    try:
        zipfile.ZipFile(file).close()
    except zipfile.BadZipfile:
        return
    infile = zipfile.ZipFile(file,"a")
    other_sigs = []
    #  Simulate "os" module for passing to the hash_files function.
    class os:
        sep = "/"
        class path:
            def join(self,*paths):
                return "/".join(paths)
            def dirname(self,path):
                if "/" not in path:
                    return ""
                return path.rsplit("/",1)[0]
            def basename(self,path):
                if "/" not in path:
                    return path
                return path.rsplit("/",1)[1]
            def exists(self,path):
                try:
                    infile.getinfo(path)
                except KeyError:
                    return False
                else:
                    return True
        path = path()
    #  Careful not to inlude the outfile itself in the signature.
    def files():
        for nm in infile.namelist():
            if isinstance(outfile,basestring) and nm == outfile:
                continue
            yield nm
    hashdata = hash_files("",files(),hash=hash,read=infile.read,os=os())
    sig = base64.b64encode(key.sign(hashdata))
    #  If the file already exists, try to add our signature to it.
    #  If the data has changed, the old data is silently thrown away.
    if isinstance(outfile,basestring):
        try:
            infile.getinfo(outfile)
        except KeyError:
            pass
        else:
            offset = 0
            for ln in infile.read(outfile).split("\n"):
                offset += len(ln) + 1
                if not ln.strip():
                    break
                other_sigs.append(ln + "\n")
            olddata = infile.read(outfile)[offset:]
            if olddata != hashdata:
                other_sigs = []
    #  Write out the new hash data with prepended signature.
    if isinstance(outfile,basestring):
        data = [key.fingerprint() + " " + sig + "\n"]
        for sig2 in other_sigs:
            data.append(sig2)
        data.append("\n")
        data.append(hashdata)
        infile.writestr(outfile,"".join(data))
    else:
        outfile.write(key.fingerprint() + " " + sig + "\n")
        for sig2 in other_sigs:
            outfile.write(sig2)
        outfile.write("\n")
        outfile.write(hashdata)


def sign_py2exe_app(appdir,key=None,hash="sha1",check_modules=None):
    """Sign the py2exe app found in the specified directory.

    This function signs the bundled modules found in the given py2exe app
    directory, and modifies each executable to bootstrap the signed imports
    machinery using the given key.

    If the "check_modules" keyword arg is specified, the bootstrapping code
    checks that only those modules were imported before signed imports were
    enabled.  It's on by default to help you avoid errors - set it to False
    to disable this check.

    The bootstrapping code is embedded directly in the executable as part of
    py2exe's PYTHONSCRIPT resource.  It should therefore be covered by a
    signature over the executable itself.
    """
    if check_modules is None:
        check_modules = ["_memimporter"]
    do_check_modules = (check_modules != False)
    #  Since the public key will be embedded in the executables, it's OK to
    #  generate a throw-away key that's purely for signing this particular app.
    if key is None:
        key = RSAKeyWithPSS.generate()
    pubkey = key.get_public_key()
    #  Build the bootstrapping code needed for each executable.
    #  We init the bootstrap objects inside a function so they get their own
    #  namespace; py2exe's own bootstrap code does a "del sys" which would
    #  play havoc with the import machinery.
    bscodestr = get_bootstrap_code()
    bscode =  """
import sys

#  Check the boot-time modules if necessary.
if %(do_check_modules)r and "signedimp" not in sys.modules:
    for mod in sys.modules:
        if mod in sys.builtin_module_names:
            continue
        if mod not in %(check_modules)r:
            err = "module '%%s' already loaded, integrity checks impossible"
            sys.stderr.write(err %% (mod,))
            sys.stderr.write("\\nTerminating the program.\\n")
            sys.exit(1)

#  Get a reference to the signedimp module, possibly by creating
#  it from raw code.
%(bscodestr)s

#  Add the specific key into the signed import machinery.
k = signedimp.%(pubkey)r
try:
    if isinstance(sys.meta_path[0],signedimp.SignedImportManager):
        sys.meta_path[0].add_valid_key(k)
    else:
        signedimp.SignedImportManager([k]).install()
except (IndexError,AttributeError):
    signedimp.SignedImportManager([k]).install()

""" % locals()
    bscode = compile(bscode,"__main__.py","exec")
    #  Hack the bootstrap code into the start of each script to be run.
    #  This unfortunately depends on some inner details of the py2exe format.
    for nm in os.listdir(appdir):
        if nm.endswith(".exe"):
            exepath = os.path.join(appdir,nm)
            try:
                appcode = winres.load_resource(exepath,u"PYTHONSCRIPT",1,0)
            except EnvironmentError:
                continue
            sz = struct.calcsize("iiii")
            (magic,optmz,bfrd,codelen) = struct.unpack("iiii",appcode[:sz])
            assert magic == 0x78563412
            codebytes = appcode[sz:-1]
            for i,c in enumerate(codebytes):
                if c == "\x00":
                    relarcname = codebytes[:i]
                    codelist = marshal.loads(codebytes[i+1:-1])
                    break
            codelist.insert(0,bscode)
            codebytes = marshal.dumps(codelist)
            appcode = struct.pack("iiii",magic,optmz,bfrd,len(codebytes)) \
                      + relarcname + "\x00" + codebytes + "\x00\x00"
            winres.add_resource(exepath,appcode,u"PYTHONSCRIPT",1,0)
    #  Sign anything that might be an importable zipfile.
    for nm in os.listdir(appdir):
        if nm.endswith(".exe") or nm.endswith(".zip"):
            try:
                sign_zipfile(os.path.join(appdir,nm),key,hash=hash)
            except zipfile.BadZipfile:
                pass
    #  Sign the appdir itself.  Doing this last means it will generate
    #  a correct hash for the modified exes and zipfiles.
    sign_directory(appdir,key,hash=hash)


def sign_py2app_bundle(appdir,key=None,hash="sha1",check_modules=None):
    """Sign the py2app bundle found in the specified directory.

    This function signs the bundled modules found in the given py2app bundle
    directory, and modifies the bootstrapping code to enable signed imports
    using the given key.

    If the "check_modules" keyword arg is specified, the bootstrapping code
    checks that only those modules were imported before signed imports were
    enabled.  It's on by default to help you avoid errors - set it to False
    to disable this check.

    The bootstrapping code is embedded into the app's __boot__.py script.
    You'll need to be sure to sign this file as part of your applications
    signature.  The default signing scheme for OSX covers it as it's in the
    "Resources" folder, but if you write custom signing specs then you'll have
    to be careful.
    """
    if check_modules is None:
        check_modules = ["codecs","encodings","encodings.__builtin__",
                         "encodings.codecs","encodings.utf_8","copy_reg","site",
                         "abc","os","wxhack","posixpath","_abcoll","os.path",
                         "genericpath","stat","warnings","types","linecache",
                         "encodings.aliases","encodings.encodings","readline",
                         "UserDict","zlib"]
    do_check_modules = (check_modules != False)
    #  Since the public key will be embedded in the executables, it's OK to
    #  generate a throw-away key that's purely for signing this particular app.
    if key is None:
        key = RSAKeyWithPSS.generate()
    pubkey = key.get_public_key()
    #  Build the bootstrap code and put it at start of __boot__.py.
    bscodestr = get_bootstrap_code()
    bscode =  """
import sys

#  Check the boot-time modules if necessary.
if %(do_check_modules)r and "signedimp" not in sys.modules:
    for mod in sys.modules:
        if mod in sys.builtin_module_names:
            continue
        if mod not in %(check_modules)r:
            err = "module '%%s' already loaded, integrity checks impossible"
            sys.stderr.write(err %% (mod,))
            sys.stderr.write("\\nTerminating the program.\\n")
            sys.exit(1)

#  Get a reference to the signedimp module, possibly by creating
#  it from raw code.
%(bscodestr)s

#  Add the specific key into the signed import machinery.
k = signedimp.%(pubkey)r
try:
    if isinstance(sys.meta_path[0],signedimp.SignedImportManager):
        sys.meta_path[0].add_valid_key(k)
    else:
        signedimp.SignedImportManager([k]).install()
except (IndexError,AttributeError):
    signedimp.SignedImportManager([k]).install()

""" % locals()
    bsfile = os.path.join(appdir,"Contents","Resources","__boot__.py")
    with open(bsfile,"r+") as f:
        oldcode = f.read()
        f.seek(0)
        f.write(bscode)
        f.write(oldcode)
    #  Sign the main library.zip
    libdir = os.path.join(appdir,"Contents","Resources","lib")
    libdir = os.path.join(libdir,"python%d.%d"%sys.version_info[:2])
    for nm in os.listdir(libdir):
        if nm.endswith(".zip"):
            sign_zipfile(os.path.join(libdir,nm),key,hash=hash)
    #  Sign a variety of potential code dirs
    try:
        sign_directory(os.path.join(libdir,"lib-dynload"),key,hash=hash)
    except EnvironmentError:
        pass
    try:
        sign_directory(os.path.join(libdir,"site-packages"),key,hash=hash)
    except EnvironmentError:
        pass
    try:
        sign_directory(os.path.join(libdir,"lib-tk"),key,hash=hash)
    except EnvironmentError:
        pass
    try:
        sign_directory(libdir,key,hash=hash)
    except EnvironmentError:
        pass
    #  Sign the main Resources dir.
    sign_directory(os.path.join(appdir,"Contents","Resources"),key,hash=hash)
    

def sign_cxfreeze_app(appdir,key=None,hash="sha1",check_modules=None):
    """Sign the cxfreeze app found in the specified directory.

    This function signs the modules found in the given cxfreeze application
    directory, and modifies each executable to bootstrap signed imports using
    the given key.

    If the "check_modules" keyword arg is specified, the bootstrapping code
    checks that only those modules were imported before signed imports were
    enabled.  It's on by default to help you avoid errors - set it to False
    to disable this check.

    The bootstrapping code is embedded into each executable as an appended
    zipfile, which cxfreeze will helpfully place as the first item on sys.path.
    Due to an unfortunate limitation of the zipimport module, you'll need a
    patched version of python if you intend to sign the executables with e.g.
    Microsoft Authenticode; see Issue 5950 for more details:

        http://bugs.python.org/issue5950

    """
    initmod = "cx_Freeze__init__"
    if check_modules is None:
        check_modules = ["codecs","encodings","encodings.__builtin__",
                         "encodings.codecs","encodings.utf_8",
                         "encodings.aliases","encodings.encodings"]
    do_check_modules = (check_modules != False)
    #  Since the public key will be embedded in the executables, it's OK to
    #  generate a throw-away key that's purely for signing this particular app.
    if key is None:
        key = RSAKeyWithPSS.generate()
    pubkey = key.get_public_key()
    #  Build the bootstrap code to be inserted into each executable.  Since
    #  it replaces the cx_Freeze__init__ script it needs to exec that once
    #  the signed imports are in place.
    bscode_tmplt =  """
import sys

#  Check the boot-time modules if necessary.
if %(do_check_modules)r and "signedimp" not in sys.modules:
    for mod in sys.modules:
        if mod == "signedimp" or mod.startswith("signedimp."):
            continue
        if mod in sys.builtin_module_names:
            continue
        if mod not in %(check_modules)r:
            err = "module '%%s' already loaded, integrity checks impossible"
            sys.stderr.write(err %% (mod,))
            sys.stderr.write("\\nTerminating the program.\\n")
            sys.exit(1)

#  Since it's bundled into a zipfile, we always get at signedimp by
#  just importing it.  This will re-use an existing version if loaded.
import signedimp

#  Add the specific key into the signed import machinery.
k = signedimp.%(pubkey)r
try:
    if isinstance(sys.meta_path[0],signedimp.SignedImportManager):
        sys.meta_path[0].add_valid_key(k)
    else:
        signedimp.SignedImportManager([k]).install()
except (IndexError,AttributeError):
    signedimp.SignedImportManager([k]).install()

#  Bootstrap the original cx_Freeze__init__ module.
#  If it was in the appended zipfile, we're given it as a marshalled string.
#  If not, we need to search for it in the other zipfiles.
if %(has_initcode)r:
    import marshal
    exec marshal.loads(%(initcode)r)
else:
    import zipimport
    initmod = "cx_Freeze__init__"
    try:
        imp = zipimport.zipimporter(EXCLUSIVE_ZIP_FILE_NAME)
        imp.find_module(initmod)
        INITSCRIPT_ZIP_FILE_NAME = EXCLUSIVE_ZIP_FILE_NAME
    except ImportError:
        imp = zipimport.zipimporter(SHARED_ZIP_FILE_NAME)
        imp.find_module(initmod)
        INITSCRIPT_ZIP_FILE_NAME = SHARED_ZIP_FILE_NAME
    code = imp.get_code(initmod)
    exec code
    
"""
    #  Add the bootstrapping code to any executables found in the dir.
    for nm in os.listdir(appdir):
        fpath = os.path.join(appdir,nm)
        if not os.path.isfile(fpath) or not _is_executable(fpath):
            continue
        zf = zipfile.PyZipFile(fpath,"a")
        try:
            #  If it contains the init module already, we'll need to
            #  grab its code to bootstrap into it.
            try:
                initcode = repr(zf.read(initmod+".pyc")[8:])
            except KeyError:
                initcode = ""
            #  Store our own code as the cxfreeze init module
            has_initcode = bool(initcode)
            bssrc = bscode_tmplt % locals()
            bscode = imp.get_magic() + struct.pack("<i",time.time())
            bscode += marshal.dumps(compile(bssrc,initmod+".py","exec"))
            zf.writestr(initmod+".pyc",bscode)
            #  Make sure the signedimp module is bundled into the zipfile
            zf.writepy(os.path.dirname(signedimp.__file__))
            #  The python interpreter itself tries to import various encodings
            #  modules on startup.  They must also be bundled into the exe.
            #  Fortunately cxfreeze usually includes them as frozen modules
            #  directly into the exe; this is just to make sure.
            for nm2 in os.listdir(appdir):
                if nm2 == nm or not os.path.isfile(os.path.join(appdir,nm2)):
                    continue
                try:
                    zf2 = zipfile.ZipFile(os.path.join(appdir,nm2))
                except zipfile.BadZipfile:
                    pass
                else:
                    try:
                        for znm in zf2.namelist():
                            for incmod in ("encodings","codecs"):
                                if znm.startswith(incmod):
                                    zf.writestr(znm,zf2.read(znm))
                    finally:
                        zf2.close()
        finally:
            zf.close()
    #  Sign any zipfiles in the appdir (inlcuding the exes from above)
    for nm in os.listdir(appdir):
        if not os.path.isfile(os.path.join(appdir,nm)):
            continue
        try:
            sign_zipfile(os.path.join(appdir,nm),key,hash=hash)
        except (zipfile.BadZipfile,EnvironmentError):
            pass
    #  Sign the main app dir.
    sign_directory(appdir,key,hash=hash)



def _is_executable(path):
    if sys.platform == "win32":
        return path.endswith(".exe")
    else:
        p = subprocess.Popen(["file",path],stdout=subprocess.PIPE)
        return ("executable" in p.stdout.read())


def _is_in_package(root,path,os=os):
    """Check whether the given path is inside a package directory structure.

    This is used to decide whether to sign it as a module or a datafile.
    """
    while path != root:
        for (suffix,_,_) in imp.get_suffixes():
            if os.path.exists(os.path.join(path,"__init__"+suffix)):
                break
        else:
            return False
        path = os.path.dirname(path)
    return True


def _get_module_basename(filepath,os=os):
    """Get the base name of the module at the given file path."""
    for (suffix,_,_) in imp.get_suffixes():
        if filepath.endswith(suffix):
            return filepath[:-1*len(suffix)]
    return None

def _read_file(path):
    """Default read() function for use with hash_files()."""
    with open(path,"rb") as f:
        return f.read()

def hash_files(path,files=None,hash="sha1",read=_read_file,os=os):
    """Generate unsigned hash data for files under the given path.

    Here 'path' must be the root of the directory being signed and 'files'
    an iterable yielding file paths under that root.  If given, the optional
    arguments 'read' and 'os' are used in place of the builtins with the same
    name - this might be useful if you're hashing some sort of virtual dir.
    """
    output = [hash]
    if hash == "sha1":
        hash = sha1
    elif hash == "md5":
        hash = md5
    else:
        raise ValueError("unknown hash type: %s" % (hash,))
    modhashes = {}
    datahashes = {}
    while path.endswith(os.sep):
        path = path[:-1]
    if path:
        prefixlen = len(path) + 1
    else:
        prefixlen = 0
    if files is None:
        def files():
            for (dirnm,_,filenms) in os.walk(path):
                for filenm in filenms:
                    yield os.path.join(dirnm,filenm)
        files = files()
    for filepath in files:
        #  If we're not in a package, sign everything as a datafile.
        #  If we are, try to sign files as a module first.
        if not _is_in_package(path,os.path.dirname(filepath),os=os):
            #  Just sign it as a datafile
            hashname = filepath[prefixlen:].replace(os.sep,"/")
            datahashes[hashname] = hash(read(filepath)).hexdigest()
        else:
            basenm = _get_module_basename(filepath,os=os)
            if basenm is None:
                #  Just sign it as a datafile
                hashname = filepath[prefixlen:].replace(os.sep,"/")
                datahashes[hashname] = hash(read(filepath)).hexdigest()
            else:
                #  We sign the concatentation of all files in the order
                #  they are found by the import machinery.
                modname = basenm[prefixlen:].replace(os.sep,".")
                if modname not in modhashes:
                    moddata = []
                    for (suffix,_,_) in imp.get_suffixes():
                        if os.path.exists(basenm+suffix):
                            modpath = basenm+suffix
                            moddata.append(read(modpath))
                    moddata = "\x00".join(moddata)
                    modhashes[modname] = hash(moddata).hexdigest()
    #  Concatenate the various hashes.  Put then in sorted order so
    #  it's easy to locate a particular hash by hand.
    for nm,hash in sorted(modhashes.items()):
        output.append("m %s %s" % (hash,nm))
    for nm,hash in sorted(datahashes.iteritems()):
        output.append("d %s %s" % (hash,nm))
    return "\n".join(output)


