"""

  refreeze:  manipulate frozen python applications.

"""

from __future__ import absolute_import
from __future__ import with_statement

import os
import sys
import imp
import tempfile
import struct
import marshal
import time
import zipfile
import inspect

if sys.platform != "win32":
    class k32(object):
        def __getattibute__(self,attr):
            raise RuntimeError("only available on win32")
    k32 = k32()
else:
    import ctypes
    from ctypes import WinError, windll, c_char, POINTER, byref, sizeof
    k32 = windll.kernel32

LOAD_LIBRARY_AS_DATAFILE = 0x00000002
RT_ICON = 3
RT_VERSION = 16
RT_MANIFEST = 24


# AFAIK 1033 is some sort of "default" language.
# Is it (LANG_NEUTRAL,SUBLANG_NEUTRAL)?
_DEFAULT_RESLANG = 1033


def load_resource(filename_or_handle,res_type,res_id,res_lang=_DEFAULT_RESLANG):
    """Load a resource from the given filename or module handle.

    The "res_type" and "res_id" arguments identify the particular resource
    to be loaded, along with the "res_lang" argument if given.  The contents
    of the specified resource are returned as a string.
    """
    if isinstance(filename_or_handle,basestring):
        filename = filename_or_handle
        if not isinstance(filename,unicode):
            filename = filename.decode(sys.getfilesystemencoding())
        l_handle = k32.LoadLibraryExW(filename,None,LOAD_LIBRARY_AS_DATAFILE)
        if not l_handle:
            raise ctypes.WinError()
        free_library = True
    else:
        l_handle = filename_or_handle
        free_library = False
    try:
        r_handle = k32.FindResourceExW(l_handle,res_type,res_id,res_lang)
        if not r_handle:
            raise WinError()
        r_size = k32.SizeofResource(l_handle,r_handle)
        if not r_size:
            raise WinError()
        r_info = k32.LoadResource(l_handle,r_handle)
        if not r_info:
            raise WinError()
        r_ptr = k32.LockResource(r_info)
        if not r_ptr:
            raise WinError()
        resource = ctypes.cast(r_ptr,POINTER(c_char))[0:r_size]
        return resource
    finally:
        if free_library:
            k32.FreeLibrary(l_handle)


def add_resource(filename,resource,res_type,res_id,res_lang=_DEFAULT_RESLANG):
    """Add a resource to the given filename.

    The "res_type" and "res_id" arguments identify the particular resource
    to be added, along with the "res_lang" argument if given.  The contents
    of the specified resource must be provided as a string.
    """
    if not isinstance(filename,unicode):
        filename = filename.decode(sys.getfilesystemencoding())
    l_handle = k32.BeginUpdateResourceW(filename,0)
    if not l_handle:
        raise WinError()
    res_info = (resource,len(resource))
    if not k32.UpdateResourceW(l_handle,res_type,res_id,res_lang,*res_info):
        raise WinError()
    if not k32.EndUpdateResourceW(l_handle,0):
        raise WinError()


class FrozenApp(object):
    """Abstract base class representing a frozen Python application."""

    def __init__(self,path):
        self.path = path

    def _obj2code(self,obj):
        """Convert an object to some python source code.

        Iterables are flattened, None is elided, strings are included verbatim,
        open files are read and anything else is passed to inspect.getsource().
        """
        if obj is None:
            return ""
        if isinstance(obj,basestring):
            return obj
        if hasattr(obj,"read"):
            return obj.read()
        try:
            return "\n\n\n".join(self._obj2code(i) for i in obj)
        except TypeError:
            return inspect.getsource(obj)

    def append_code(self,code):
        """Run the given code after all other code for the frozen app."""
        raise NotImplementedError

    def prepend_code(self,code):
        """Run the given code before any other code for the frozen app."""
        raise NotImplementedError

    def replace_code(self,code):
        """Run the given code instead of any other code for the frozen app."""
        raise NotImplementedError
        

class Py2Exe(FrozenApp):
    """App frozen with py2exe."""

    def __init__(self,path):
        super(Py2Exe,self).__init__(path)
        appcode = load_resource(self.path,u"PYTHONSCRIPT",1,0)
        sz = struct.calcsize("iiii")
        (self._magic,self._optmz,self._bfrd,codelen) = struct.unpack("iiii",appcode[:sz])
        assert self._magic == 0x78563412
        codebytes = appcode[sz:-1]
        for i,c in enumerate(codebytes):
            if c == "\x00":
                self._relarcname = codebytes[:i]
                self._codelist = marshal.loads(codebytes[i+1:-1])
                break
        else:
            raise ValueErrr("no frozen bytecode found")

    def _save_codelist(self):
        codebytes = marshal.dumps(self._codelist)
        appcode = struct.pack("iiii",self._magic,self._optmz,self._bfrd,
                              len(codebytes)) 
        appcode += self._relarcname + "\x00" + codebytes + "\x00\x00"
        add_resource(self.path,appcode,u"PYTHONSCRIPT",1,0)

    def prepend_code(self,code):
        src = self._obj2code(code)
        code = compile(src,"__main__.py","exec")
        self._codelist.insert(0,code)
        self._save_codelist()

    def append_code(self,code):
        src = self._obj2code(code)
        code = compile(src,"__main__.py","exec")
        self._codelist.append(code)
        self._save_codelist()

    def replace_code(self,code):
        src = self._obj2code(code)
        code = compile(src,"__main__.py","exec")
        self._codelist[:] = [code]
        self._save_codelist()
        


class Py2App(FrozenApp):

    def __init__(self,path):
        super(Py2App,self).__init__(path)
        self._resdir = os.path.join(self.path,"Contents","Resources")
        self._bootscript = os.path.join(self._resdir,"__boot__.py")
        if not os.path.exists(self._bootscript):
            raise ValueError("not a py2app bundle")

    def prepend_code(self,code):
        code = self._obj2code(code)
        with open(self._bootscript,"r+") as f:
            oldcode = f.read()
            f.seek(0)
            f.write(code)
            f.write(oldcode)

    def append_code(self,code):
        code = self._obj2code(code)
        with open(self._bootscript,"r+") as f:
            oldcode = f.read()
            f.seek(0)
            f.write(oldcode)
            f.write(code)

    def replace_code(self,code):
        code = self._obj2code(code)
        with open(self._bootscript,"w") as f:
            f.write(code)




class CXFreeze(FrozenApp):

    INITMOD = "cx_Freeze__init__"

    def __init__(self,path):
        super(CXFreeze,self).__init__(path)
        # TODO: how to check if it's a cxfreeze app?

    def prepend_code(self,code):
        code = self._obj2code(code)
        zf = zipfile.PyZipFile(self.path,"a")
        try:
            try:
                initcode = zf.read(self.INITMOD+".pyc")[8:]
            except KeyError:
                #  No initcode.  Do out own thing, then chainload.
                code += _CXFREEZE_CHAINLOAD_INITMOD
            else:
                #  initcode already present, store it marshalled
                code += "\nimport marshal; exec marshal.loads(%r)"%(initcode,)
            bcode = imp.get_magic() + struct.pack("<i",time.time())
            bcode += marshal.dumps(compile(code,self.INITMOD+".py","exec"))
            zf.writestr(self.INITMOD+".pyc",bcode)
        finally:
            zf.close()

    def append_code(self,code):
        code = self._obj2code(code)
        zf = zipfile.PyZipFile(self.path,"a")
        try:
            try:
                initcode = zf.read(self.INITMOD+".pyc")[8:]
            except KeyError:
                #  No initcode.  Do out own thing, then chainload.
                code = _CXFREEZE_CHAINLOAD_INITMOD + "\n" + code
            else:
                #  initcode already present, store it marshalled
                code = "import marshal; exec marshal.loads(%r)\n"%(initcode,) \
                       + code
            bcode = imp.get_magic() + struct.pack("<i",time.time())
            bcode += marshal.dumps(compile(code,self.INITMOD+".py","exec"))
            zf.writestr(self.INITMOD+".pyc",bcode)
        finally:
            zf.close()

    def replace_code(self,code):
        code = self._obj2code(code)
        zf = zipfile.PyZipFile(self.path,"a")
        try:
            bcode = imp.get_magic() + struct.pack("<i",time.time())
            bcode += marshal.dumps(compile(code,self.INITMOD+".py","exec"))
            zf.writestr(self.INITMOD+".pyc",bcode)
        finally:
            zf.close()


_CXFREEZE_CHAINLOAD_INITMOD = """
try:
    from zipimportx import zipimporter
except ImportError:
    from zipimport import zipimporter
initmod = "cx_Freeze__init__"
try:
    zimp = zipimporter(EXCLUSIVE_ZIP_FILE_NAME)
    zimp.find_module(initmod)
    INITSCRIPT_ZIP_FILE_NAME = EXCLUSIVE_ZIP_FILE_NAME
except ImportError:
    zimp = zipimporter(SHARED_ZIP_FILE_NAME)
    zimp.find_module(initmod)
    INITSCRIPT_ZIP_FILE_NAME = SHARED_ZIP_FILE_NAME
code = zimp.get_code(initmod)
exec code
"""

