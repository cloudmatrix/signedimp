
from __future__ import with_statement

import unittest

import os
import sys
import shutil
import tempfile
import random
import subprocess
import compileall
import zipfile
import pkgutil

import signedimp
import signedimp.tools
from signedimp.crypto.rsa import RSAKeyWithPSS

#  setuptools likes to be imported before anything else that
#  might monkey-patch distutils.  We don't actually use it,
#  this is just to avoid errors with cx_Freeze.
try:
    import setuptools
except ImportError:
    pass

try:
    import pkg_resources
except ImportError:
    pkg_resources = None


def popen(cmd,**kwds):
    kwds.setdefault("stdout",subprocess.PIPE)
    kwds.setdefault("stderr",subprocess.PIPE)
    return subprocess.Popen(cmd,**kwds)


KEY = RSAKeyWithPSS.generate(1024)

class TestSignedImp_DefaultImport(unittest.TestCase):

    def setUp(self):
        self.tdir = tempfile.mkdtemp()
        #  Ensure we have signedimp in the test environment.
        shutil.copytree(os.path.dirname(os.path.dirname(__file__)),
                        os.path.join(self.tdir,"signedimp"))
      
        #  Ensure we have pkgutil and pkg_resources in the test environment.
        with open(pkgutil.__file__,"rb") as fIn:
            with open(os.path.join(self.tdir,"pkgutil.pyc"),"wb") as fOut:
                shutil.copyfileobj(fIn,fOut)
        if pkg_resources is not None:
            pkgres_code = pkg_resources.resource_string("pkg_resources",
                                                        "pkg_resources.pyc")
            with open(os.path.join(self.tdir,"pkg_resources.pyc"),"wb") as f:
                f.write(pkgres_code)
        #  Create the "signedimp_test" module.
        self.pkgdir = os.path.join(self.tdir,"signedimp_test")
        os.mkdir(self.pkgdir)
        with open(os.path.join(self.pkgdir,"__init__.py"),"w") as f:
            f.write("from pkgutil import extend_path\n")
            f.write("__path__ = extend_path(__path__,__name__)\n")
        with open(os.path.join(self.pkgdir,"test1.py"),"w") as f:
            f.write("value = 7\n")
        with open(os.path.join(self.pkgdir,"test2.py"),"w") as f:
            f.write("value = 42\n")
        #  Create "signedimp_test.test3" in a namespace package.
        pkgdir2 = os.path.join(self.tdir,"subpath") 
        os.mkdir(pkgdir2)
        pkgdir2 = os.path.join(self.tdir,"subpath","signedimp_test") 
        os.mkdir(pkgdir2)
        with open(os.path.join(pkgdir2,"__init__.py"),"w") as f:
            f.write("from pkgutil import extend_path\n")
            f.write("__path__ = extend_path(__path__,__name__)\n")
        with open(os.path.join(pkgdir2,"test3.py"),"w") as f:
            f.write("value = 256\n")
        #  Create "si_test2" as an alias for signedimp_test
        pkgdir2 = os.path.join(self.tdir,"si_test2") 
        os.mkdir(pkgdir2)
        with open(os.path.join(pkgdir2,"__init__.py"),"w") as f:
            f.write("import os\n")
            f.write("d = os.path.dirname(os.path.dirname(__file__))\n")
            f.write("__path__.append(os.path.join(d,'signedimp_test'))\n")
        #  Compile everything to bytecode to ensure a steady state.
        compileall.compile_dir(self.tdir,quiet=True)
        compileall.compile_dir(os.path.join(self.tdir,"subpath"),quiet=True)

    def tearDown(self):
        shutil.rmtree(self.tdir)

    def _runpy(self,*code,**kwds):
        cmd = [sys.executable,"-c"]
        paths = (repr(self.tdir),repr(os.path.join(self.tdir,"subpath")),)
        bscode = "import sys; sys.path = [%s,%s]; " % paths
        if "extra_path" in kwds:
            bscode += " sys.path.extend(%s); " % (repr(kwds["extra_path"]),)
        for stmt in code:
            bscode += stmt + "; "
        cmd.append(bscode)
        return popen(cmd)

    def signit(self,k):
        signedimp.tools.sign_directory(self.tdir,k)
        signedimp.tools.sign_directory(os.path.join(self.tdir,"subpath"),k)

    def readPackagedFile(self,path):
        with open(os.path.join(self.tdir,path),"rb") as f:
            return f.read()

    def writePackagedFile(self,path,data):
        with open(os.path.join(self.tdir,path),"wb") as f:
            f.write(data)

    def test_the_test(self):
        p = self._runpy("from signedimp_test.test1 import value",
                        "print value")
        self.assertEquals(p.wait(),0)
        self.assertEquals(p.stdout.read().strip(),"7")

    def test_no_signatures_means_failure(self):
        p = self._runpy("from signedimp import SignedImportManager",
                        "sim = SignedImportManager()",
                        "sim.install()",
                        "import signedimp_test")
        self.assertNotEquals(p.wait(),0)
        self.assertTrue("IntegrityCheckMissing" in p.stderr.read())

    def test_signed_dir_succeeds(self):
        self.signit(KEY)
        p = self._runpy("from signedimp import SignedImportManager",
                        "from signedimp import RSAKeyWithPSS",
                        "k = %s" % (repr(KEY.get_public_key(),)),
                        "sim = SignedImportManager([k])",
                        "sim.install()",
                        "import signedimp_test.test1",
                        "print signedimp_test.test1.value")
        self.assertEquals(p.wait(),0)
        self.assertEquals(p.stdout.read().strip(),"7")
 
    def test_corrupted_sig_fails(self):
        self.signit(KEY)
        sigdata = self.readPackagedFile(signedimp.HASHFILE_NAME)
        if sigdata[50] == "A":
            sigdata = sigdata[:50] + "B" + sigdata[51:]
        else:
            sigdata = sigdata[:50] + "A" + sigdata[51:]
        self.writePackagedFile(signedimp.HASHFILE_NAME,sigdata)
        p = self._runpy("from signedimp import SignedImportManager",
                        "from signedimp import RSAKeyWithPSS",
                        "k = %s" % (repr(KEY.get_public_key(),)),
                        "sim = SignedImportManager([k])",
                        "sim.install()",
                        "import signedimp_test.test1",
                        "print signedimp_test.test1.value")
        self.assertNotEquals(p.wait(),0)
        self.assertTrue("bad signature" in p.stderr.read())

    def test_corrupted_hash_fails(self):
        self.signit(KEY)
        sigdata = self.readPackagedFile(signedimp.HASHFILE_NAME)
        new_sigdata = []
        for ln in sigdata.split("\n"):
            if "signedimp_test.test2" not in ln:
                new_sigdata.append(ln)
            elif ln[10] == "c":
                new_sigdata.append(ln[:10]+"b"+ln[11:])
            else:
                new_sigdata.append(ln[:10]+"c"+ln[11:])
        new_sigdata = "\n".join(new_sigdata)
        self.writePackagedFile(signedimp.HASHFILE_NAME,new_sigdata)
        p = self._runpy("from signedimp import SignedImportManager",
                        "from signedimp import RSAKeyWithPSS",
                        "k = %s" % (repr(KEY.get_public_key(),)),
                        "sim = SignedImportManager([k])",
                        "sim.install()",
                        "import signedimp_test.test1",
                        "print signedimp_test.test1.value")
        self.assertNotEquals(p.wait(),0)
        self.assertTrue("bad signature" in p.stderr.read())

    def test_modified_file_fails_on_import(self):
        self.signit(KEY)
        self.writePackagedFile("signedimp_test/test2.py","value = 12")
        p = self._runpy("from signedimp import SignedImportManager",
                        "from signedimp import RSAKeyWithPSS",
                        "k = %s" % (repr(KEY.get_public_key(),)),
                        "sim = SignedImportManager([k])",
                        "sim.install()",
                        "import signedimp_test.test1",
                        "print signedimp_test.test1.value")
        self.assertEquals(p.wait(),0)
        self.assertEquals(p.stdout.read().strip(),"7")
        p = self._runpy("from signedimp import SignedImportManager",
                        "from signedimp import RSAKeyWithPSS",
                        "k = %s" % (repr(KEY.get_public_key(),)),
                        "sim = SignedImportManager([k])",
                        "sim.install()",
                        "import signedimp_test.test2",)
        self.assertNotEquals(p.wait(),0)
        self.assertTrue("invalid hash" in p.stderr.read())

    def test_namespace_packages(self):
        self.signit(KEY)
        p = self._runpy("from signedimp import SignedImportManager",
                        "from signedimp import RSAKeyWithPSS",
                        "k = %s" % (repr(KEY.get_public_key(),)),
                        "sim = SignedImportManager([k])",
                        "sim.install()",
                        "import signedimp_test.test3",
                        "print signedimp_test.test3.value")
        self.assertEquals(p.wait(),0)
        self.assertEquals(p.stdout.read().strip(),"256")

    if pkg_resources is not None:
        def test_pkgres(self):
            self.signit(KEY)
            p = self._runpy("import pkg_resources",
                            "from signedimp import SignedImportManager",
                            "from signedimp import RSAKeyWithPSS",
                            "k = %s" % (repr(KEY.get_public_key(),)),
                            "sim = SignedImportManager([k])",
                            "sim.install()",
                            "import signedimp.pkgres",
                            "m = 'signedimp_test'",
                            "print pkg_resources.resource_listdir(m,'')",
                             extra_path=sys.path)
            self.assertEquals(p.wait(),0)
            exec "items = " + p.stdout.read().strip()
            self.assertTrue("test1.py" in items)
            self.assertTrue("test2.py" in items)
            self.assertFalse("test3.py" in items)


class TestSignedImp_ZipImport(TestSignedImp_DefaultImport):

    def _runpy(self,*code,**kwds):
        cmd = [sys.executable,"-c"]
        libpath = os.path.join(self.tdir,"library.zip")
        if not os.path.exists(libpath):
            self.zipit()
        bscode = "import sys; sys.path = [%s]; " % (repr(libpath),)
        if "extra_path" in kwds:
            bscode += " sys.path.extend(%s); " % (repr(kwds["extra_path"]),)
        for stmt in code:
            bscode += stmt + "; "
        cmd.append(bscode)
        return popen(cmd)

    def zipit(self):
        libpath = os.path.join(self.tdir,"library.zip")
        zf = zipfile.ZipFile(libpath,"w")
        for (dirnm,_,filenms) in os.walk(self.tdir):
            for filenm in filenms:
                filepath = os.path.join(dirnm,filenm)
                if filepath != libpath:
                    relpath = filepath[len(self.tdir)+1:]
                    zf.write(filepath,relpath)
        zf.close()

    def signit(self,k):
        self.zipit()
        libpath = os.path.join(self.tdir,"library.zip")
        signedimp.tools.sign_zipfile(libpath,k)

    def readPackagedFile(self,path):
        libpath = os.path.join(self.tdir,"library.zip")
        zf = zipfile.ZipFile(libpath,"r")
        return zf.read(path)

    def writePackagedFile(self,path,data):
        libpath = os.path.join(self.tdir,"library.zip")
        zf = zipfile.ZipFile(libpath,"a")
        zf.writestr(path,data)

    def test_namespace_packages(self):
        pass



try:
    import py2exe
except ImportError:
    pass
else:
    from distutils.core import setup as dist_setup

    class TestSignedImp_py2exe(unittest.TestCase):

        def setUp(self):
            self.tdir = tempfile.mkdtemp()
            scriptfile = os.path.join(self.tdir,"script.py")
            self.distdir = distdir = os.path.join(self.tdir,"dist")
            with open(scriptfile,"w") as f:
                f.write("import signedimp.crypto.rsa\n")
            dist_setup(name="testapp",version="0.1",scripts=[scriptfile],
                       options={"bdist":{"dist_dir":distdir}},
                       console=[scriptfile],
                       script_args=["py2exe"])

        def tearDown(self):
            for _ in xrange(10):
                try:
                    shutil.rmtree(self.tdir)
                    break
                except EnvironmentError:
                    pass

        def test_the_test(self):
            p = popen(os.path.join(self.distdir,"script.exe"))
            self.assertEquals(p.wait(),0)

        def test_signed_app_succeeds(self):
            signedimp.tools.sign_py2exe_app(self.distdir)
            p = popen(os.path.join(self.distdir,"script.exe"))
            self.assertEquals(p.wait(),0)

        def test_unsigned_app_fails(self):
            signedimp.tools.sign_py2exe_app(self.distdir)
            zf = zipfile.ZipFile(os.path.join(self.distdir,"library.zip"),"a")
            zf.writestr(signedimp.HASHFILE_NAME,"")
            p = popen(os.path.join(self.distdir,"script.exe"))
            self.assertNotEquals(p.wait(),0)

        def test_modified_app_fails(self):
            signedimp.tools.sign_py2exe_app(self.distdir)
            zf = zipfile.ZipFile(os.path.join(self.distdir,"library.zip"),"a")
            zf.writestr("signedimp/crypto/__init__.py","")
            p = popen(os.path.join(self.distdir,"script.exe"))
            self.assertNotEquals(p.wait(),0)

        def test_unchecked_modules_fails(self):
            signedimp.tools.sign_py2exe_app(self.distdir,check_modules=[])
            p = popen(os.path.join(self.distdir,"script.exe"))
            self.assertNotEquals(p.wait(),0)

        def test_disabled_check_modules_succeeds(self):
            signedimp.tools.sign_py2exe_app(self.distdir,check_modules=False)
            p = popen(os.path.join(self.distdir,"script.exe"))
            self.assertEquals(p.wait(),0)

        def test_replacement_load_dynamic_is_called(self):
            #  py2exe loads .pyd via a stub that calls imp.load_dynamic().
            #  Corrupt one and make sure it's detected as invalid.
            signedimp.tools.sign_py2exe_app(self.distdir)
            dynlib = "Crypto.PublicKey._fastmath.pyd"
            with open(os.path.join(self.distdir,dynlib),"ab") as f:
                f.write("malicious code")
            p = popen(os.path.join(self.distdir,"script.exe"))
            err = p.stderr.read()
            self.assertNotEquals(p.wait(),0)
            self.assertTrue("invalid hash" in err)
            self.assertTrue("Crypto.PublicKey._fastmath" in err)

try:
    import cx_Freeze
except ImportError:
    pass
else:

    class TestSignedImp_cxfreeze(unittest.TestCase):

        def setUp(self):
            self.tdir = tempfile.mkdtemp()
            scriptfile = os.path.join(self.tdir,"script.py")
            self.distdir = distdir = os.path.join(self.tdir,"dist")
            with open(scriptfile,"w") as f:
                f.write("import signedimp.crypto.rsa\n")
            f = cx_Freeze.Freezer([cx_Freeze.Executable(scriptfile)],
                                  targetDir=self.distdir)
            f.Freeze()
            if sys.platform == "win32":
                self.scriptexe = os.path.join(self.distdir,"script.exe")
            else:
                self.scriptexe = os.path.join(self.distdir,"script")

        def tearDown(self):
            for _ in xrange(10):
                try:
                    shutil.rmtree(self.tdir)
                    break
                except EnvironmentError:
                    pass

        def test_the_test(self):
            p = popen(self.scriptexe)
            self.assertEquals(p.wait(),0)

        def test_signed_app_succeeds(self):
            signedimp.tools.sign_cxfreeze_app(self.distdir)
            p = popen(self.scriptexe)
            self.assertEquals(p.wait(),0)

        def test_unsigned_app_fails(self):
            signedimp.tools.sign_cxfreeze_app(self.distdir)
            zf = zipfile.ZipFile(self.scriptexe,"a")
            zf.writestr(signedimp.HASHFILE_NAME,"")
            zf.close()
            p = popen(self.scriptexe)
            self.assertNotEquals(p.wait(),0)

        def test_modified_app_fails(self):
            signedimp.tools.sign_cxfreeze_app(self.distdir)
            zf = zipfile.ZipFile(self.scriptexe,"a")
            zf.writestr("signedimp/crypto/__init__.py","")
            zf.close()
            p = popen(self.scriptexe)
            self.assertNotEquals(p.wait(),0)

        def test_unchecked_modules_fails(self):
            #  cxfreeze on win32 doesn't import any non-builtin modules.
            if sys.platform != "win32":
                signedimp.tools.sign_cxfreeze_app(self.distdir,check_modules=[])
                p = popen(self.scriptexe)
                self.assertNotEquals(p.wait(),0)

        def test_disabled_check_modules_succeeds(self):
            signedimp.tools.sign_cxfreeze_app(self.distdir,check_modules=False)
            p = popen(self.scriptexe)
            self.assertEquals(p.wait(),0)

 
try:
    import py2app
except ImportError:
    pass
else:
    from setuptools import setup as st_setup

    class TestSignedImp_py2app(unittest.TestCase):

        def setUp(self):
            self.tdir = tempfile.mkdtemp()
            scriptfile = os.path.join(self.tdir,"script.py")
            self.distdir = distdir = os.path.join(self.tdir,"dist")
            with open(scriptfile,"w") as f:
                f.write("import signedimp.crypto.rsa\n")
            st_setup(name="testapp",version="0.1",app=[scriptfile],
                       options={"bdist":{"dist_dir":distdir}},
                       script_args=["py2app"])
            self.appdir = os.path.join(self.distdir,"testapp.app")

        def tearDown(self):
            shutil.rmtree(self.tdir)

        def test_the_test(self):
            p = popen(os.path.join(self.appdir,"Contents/MacOS/testapp"))
            self.assertEquals(p.wait(),0)

        def test_signed_app_succeeds(self):
            signedimp.tools.sign_py2app_bundle(self.appdir)
            p = popen(os.path.join(self.appdir,"Contents/MacOS/testapp"))
            self.assertEquals(p.wait(),0)

        def test_unsigned_app_fails(self):
            signedimp.tools.sign_py2app_bundle(self.appdir)
            zf = zipfile.ZipFile(os.path.join(self.appdir,"Contents/Resources/lib/python%d.%d/site-packages.zip" % sys.version_info[:2]),"a")
            zf.writestr(signedimp.HASHFILE_NAME,"")
            p = popen(os.path.join(self.appdir,"Contents/MacOS/testapp"))
            self.assertNotEquals(p.wait(),0)

        def test_modified_app_fails(self):
            signedimp.tools.sign_py2app_bundle(self.appdir)
            zf = zipfile.ZipFile(os.path.join(self.appdir,"Contents/Resources/lib/python%d.%d/site-packages.zip" % sys.version_info[:2]),"a")
            zf.writestr("signedimp/crypto/__init__.py","")
            p = popen(os.path.join(self.appdir,"Contents/MacOS/testapp"))
            self.assertNotEquals(p.wait(),0)

        def test_unchecked_modules_fails(self):
            signedimp.tools.sign_py2app_bundle(self.appdir,check_modules=[])
            p = popen(os.path.join(self.appdir,"Contents/MacOS/testapp"))
            self.assertNotEquals(p.wait(),0)

        def test_disabled_check_modules_succeeds(self):
            signedimp.tools.sign_py2app_bundle(self.appdir,check_modules=False)
            p = popen(os.path.join(self.appdir,"Contents/MacOS/testapp"))
            self.assertEquals(p.wait(),0)

class TestMisc(unittest.TestCase):

    def test_README(self):
        """Ensure that the README is in sync with the docstring.

        This test should always pass; if the README is out of sync it just
        updates it with the contents of signedimp.__doc__.
        """
        dirname = os.path.dirname
        readme = os.path.join(dirname(dirname(dirname(__file__))),"README.txt")
        if not os.path.isfile(readme):
            f = open(readme,"wb")
            f.write(signedimp.__doc__.encode())
            f.close()
        else:
            f = open(readme,"rb")
            if f.read() != signedimp.__doc__:
                f.close()
                f = open(readme,"wb")
                f.write(signedimp.__doc__.encode())
                f.close()


