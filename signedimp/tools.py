#  Copyright (c) 2009-2010, Cloud Matrix Pty. Ltd.
#  All rights reserved; available under the terms of the BSD License.
"""

  signedimp.tools:  tools for manipulating signed import datafiles


This module provides some high-level utility functions for generating the
signed module manifests required by signedimp.  For the common case of signing
a frozen application, you can use one of the following::

   sign_py2exe_app(appdirpath,key)

   sign_py2app_bundle(bundlepath,key)


To sign independently-distributed python modules, use one of the following::

   sign_directory(dirpath,key)

   sign_zipfile(zippath,key)

"""

import os
import sys
import imp
import base64
import zipfile
import marshal
import struct
import inspect

import signedimp
from signedimp.crypto.sha1 import sha1
from signedimp.crypto.md5 import md5
from signedimp.crypto.rsa import RSAKeyWithPSS

if sys.platform == "win32":
    from signedimp import winres


def get_bootstrap_code(indent=""):
    """Get sourcecode you can use for inline bootstrapping of signed imports.

    This function basically returns the source code for signedimp.bootstrap,
    with some cryptographic primitives forcibly inlined as pure python, and
    indented to the specified level.

    You would use it to boostrap signed imports in the startup script of your
    application, e.g. build a script like the following and hand it off to
    py2exe for freezing:

       SCRIPT = '''
       %s
       key = RSAKeyWithPSS(modulus,pub_exponent)
       SignedImportManager([key]).install()
       actually_start_my_appliction()
       ''' % (signedimp.tools.get_bootstrap_code(),)

    """
    def _get_source_lines(mod,indent):
        mod = __import__(mod,fromlist=["*"])
        src = inspect.getsource(mod)
        for ln in src.split("\n"):
            if "from signedimp.cryptobase." in ln:
                lnstart = ln.find("from")
                newindent = indent + ln[:lnstart]
                newmod = ln.strip()[5:].split()[0]
                for newln in _get_source_lines(newmod,newindent):
                    yield newln
            else:
                yield indent + ln
    return "\n".join(_get_source_lines("signedimp.bootstrap",indent))


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
    signs everything it finds in that file using the given key.

    By default the signed hash file is written into the root of the zipfile;
    redirect output by passing a filename or file object as 'outfile'.
    """
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
    #  Since the public key will be embedded in the executables, it's OK to
    #  generate a throw-away key that's purely for signing this particular app.
    if key is None:
        key = RSAKeyWithPSS.generate()
    #  Built the bootstrapping code needed for each executable.
    #  We init the bootstrap objects inside a function so they get their own
    #  namespace; py2exe's own bootstrap code does a "del sys" which would
    #  play havoc with the import machinery.
    bscode =  """
import sys
def _signedimp_init():
    %s
    class _signedimp_exports:
        pass
    for nm in __all__:
        setattr(_signedimp_exports,nm,staticmethod(locals()[nm]))
    return _signedimp_exports
signedimp = _signedimp_init()
if %s:
    for mod in sys.modules:
        if mod not in sys.builtin_module_names and mod not in %s:
            err = "module '%%s' already loaded, integrity checks impossible"
            sys.stderr.write(err %% (mod,))
            sys.stderr.write("\\nTerminating the program.\\n")
            sys.exit(1)
k = signedimp.%s
signedimp.SignedImportManager([k]).install()
""" % (get_bootstrap_code(indent="    "),
       (check_modules not in (False,None,)),
       repr(check_modules),
       repr(key.get_public_key()),)
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
            except zipfile.BadZipFile:
                pass
    #  Sign the appdir itself.  Doing this last means it will generate
    #  a correct hash for the modified exes and zipfiles.
    sign_directory(appdir,key,hash=hash)


def sign_py2app_bundle(appdir,key=None,hash="sha1",check_modules=None):
    """Sign the cxfreeze app found in the specified directory.

    This function signs the bundled modules found in the given py2app bundle
    directory, and modifies the bootstrapping code to enable signed imports
    using the given key.

    If the "check_modules" keyword arg is specified, the bootstrapping code
    checks that only those modules were imported before signed imports were
    enabled.  It's on by default to help you avoid errors - set it to False
    to disable this check.

    The bootstrapping code is embedded into the app's __boot__.py script.
    You'll need to be sure to sign this file as part of your applications
    signature (I *think* it will be signed by default as it's in the Resources
    folder, but haven't check yet).
    """
    if check_modules is None:
        check_modules = ["codecs","encodings","encodings.__builtin__",
                         "encodings.codecs","encodings.utf_8",
                         "encodings.aliases","encodings.encodings","readline"]
    #  Since the public key will be embedded in the executables, it's OK to
    #  generate a throw-away key that's purely for signing this particular app.
    if key is None:
        key = RSAKeyWithPSS.generate()
    #  Build the bootstrap code and put it at start of __boot__.py.
    bscode =  """
import sys
def _signedimp_init():
    %s
    class _signedimp_exports:
        pass
    for nm in __all__:
        setattr(_signedimp_exports,nm,staticmethod(locals()[nm]))
    return _signedimp_exports
signedimp = _signedimp_init()
if %s:
    for mod in sys.modules:
        if mod not in sys.builtin_module_names and mod not in %s:
            err = "module '%%s' already loaded, integrity checks impossible"
            sys.stderr.write(err %% (mod,))
            sys.stderr.write("\\nTerminating the program.\\n")
            sys.exit(1)
k = signedimp.%s
signedimp.SignedImportManager([k]).install()
""" % (get_bootstrap_code(indent="    "),
       (check_modules not in (False,None,)),
       repr(check_modules),
       repr(key.get_public_key()),)
    bsfile = os.path.join(appdir,"Contents","Resources","__boot__.py")
    with open(bsfile,"r+") as f:
        oldcode = f.read()
        f.seek(0)
        f.write(bscode)
        f.write(oldcode)
    #  Sign the main library.zip
    libdir = os.path.join(appdir,"Contents","Resources","lib")
    libdir = os.path.join(libdir,"python%d.%d"%sys.version_info[:2])
    libzip = os.path.join(libdir,"site-packages.zip")
    sign_zipfile(libzip,key,hash=hash)
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
    for nm,hash in modhashes.iteritems():
        output.append("m %s %s" % (hash,nm))
    for nm,hash in datahashes.iteritems():
        output.append("d %s %s" % (hash,nm))
    return "\n".join(output)

