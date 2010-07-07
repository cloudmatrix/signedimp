#  Copyright (c) 2009-2010, Cloud Matrix Pty. Ltd.
#  All rights reserved; available under the terms of the BSD License.
"""

  signedimp.tools:  tools for manipulating signed import datafiles

"""

import os
import imp
import base64
import zipfile

from signedimp.crypto.sha1 import sha1
from signedimp.crypto.md5 import md5
from signedimp.bootstrap import SIGNEDIMP_HASHFILE_NAME


def sign_directory(path,key,hash="sha1",outfile=SIGNEDIMP_HASHFILE_NAME):
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
    hashdata = hash_files(path,files())
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


def sign_zipfile(file,key,hash="sha1",outfile=SIGNEDIMP_HASHFILE_NAME):
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
    hashdata = hash_files("",files(),read=infile.read,os=os())
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


def _is_in_package(root,path,os=os):
    while path != root:
        for (suffix,_,_) in imp.get_suffixes():
            if os.path.exists(os.path.join(path,"__init__"+suffix)):
                break
        else:
            return False
        path = os.path.dirname(path)
    return True


def _get_module_basename(filepath,os=os):
    for (suffix,_,_) in imp.get_suffixes():
        if filepath.endswith(suffix):
            return filepath[:-1*len(suffix)]
    return None

def _read_file(path):
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


