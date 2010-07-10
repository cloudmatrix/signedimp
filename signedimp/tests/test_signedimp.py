
import unittest

import os
import sys
import shutil
import tempfile
import random
import subprocess
import compileall
import zipfile

import signedimp
import signedimp.tools
from signedimp.crypto.rsa import RSAKeyWithPSS


class TestSignedImp_DefaultImport(unittest.TestCase):

    def setUp(self):
        self.tdir = tempfile.mkdtemp()
        shutil.copytree(os.path.dirname(os.path.dirname(__file__)),
                        os.path.join(self.tdir,"signedimp"))
        self.pkgdir = os.path.join(self.tdir,"signedimp_test")
        os.mkdir(self.pkgdir)
        with open(os.path.join(self.pkgdir,"__init__.py"),"w"):
            pass
        with open(os.path.join(self.pkgdir,"test1.py"),"w") as f:
            f.write("value = 7\n")
        with open(os.path.join(self.pkgdir,"test2.py"),"w") as f:
            f.write("value = 42\n")
        compileall.compile_dir(self.tdir,quiet=True)

    def tearDown(self):
        shutil.rmtree(self.tdir)

    def _runpy(self,*code):
        cmd = [sys.executable,"-c"]
        bscode = "import sys; sys.path = [%s]; " % (repr(self.tdir,))
        for stmt in code:
            bscode += stmt + "; "
        cmd.append(bscode)
        p = subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        return p

    def signit(self,k):
        signedimp.tools.sign_directory(self.tdir,k)

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
        k = RSAKeyWithPSS.generate()
        self.signit(k)
        p = self._runpy("from signedimp import SignedImportManager",
                        "from signedimp import RSAKeyWithPSS",
                        "k = %s" % (repr(k.get_public_key(),)),
                        "sim = SignedImportManager([k])",
                        "sim.install()",
                        "import signedimp_test.test1",
                        "print signedimp_test.test1.value")
        print p.stderr.read()
        self.assertEquals(p.wait(),0)
        self.assertEquals(p.stdout.read().strip(),"7")
 
    def test_corrupted_sig_fails(self):
        k = RSAKeyWithPSS.generate()
        self.signit(k)
        sigdata = self.readPackagedFile(signedimp.HASHFILE_NAME)
        if sigdata[50] == "A":
            sigdata = sigdata[:50] + "B" + sigdata[51:]
        else:
            sigdata = sigdata[:50] + "A" + sigdata[51:]
        self.writePackagedFile(signedimp.HASHFILE_NAME,sigdata)
        p = self._runpy("from signedimp import SignedImportManager",
                        "from signedimp import RSAKeyWithPSS",
                        "k = %s" % (repr(k.get_public_key(),)),
                        "sim = SignedImportManager([k])",
                        "sim.install()",
                        "import signedimp_test.test1",
                        "print signedimp_test.test1.value")
        self.assertNotEquals(p.wait(),0)
        self.assertTrue("bad signature" in p.stderr.read())

    def test_corrupted_hash_fails(self):
        k = RSAKeyWithPSS.generate()
        self.signit(k)
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
                        "k = %s" % (repr(k.get_public_key(),)),
                        "sim = SignedImportManager([k])",
                        "sim.install()",
                        "import signedimp_test.test1",
                        "print signedimp_test.test1.value")
        self.assertNotEquals(p.wait(),0)
        self.assertTrue("bad signature" in p.stderr.read())

    def test_modified_file_fails_on_import(self):
        k = RSAKeyWithPSS.generate()
        self.signit(k)
        self.writePackagedFile("signedimp_test/test2.py","value = 12")
        p = self._runpy("from signedimp import SignedImportManager",
                        "from signedimp import RSAKeyWithPSS",
                        "k = %s" % (repr(k.get_public_key(),)),
                        "sim = SignedImportManager([k])",
                        "sim.install()",
                        "import signedimp_test.test1",
                        "print signedimp_test.test1.value")
        print p.stderr.read()
        self.assertEquals(p.wait(),0)
        self.assertEquals(p.stdout.read().strip(),"7")
        p = self._runpy("from signedimp import SignedImportManager",
                        "from signedimp import RSAKeyWithPSS",
                        "k = %s" % (repr(k.get_public_key(),)),
                        "sim = SignedImportManager([k])",
                        "sim.install()",
                        "import signedimp_test.test2",)
        self.assertNotEquals(p.wait(),0)
        self.assertTrue("invalid hash" in p.stderr.read())



class TestSignedImp_ZipImport(TestSignedImp_DefaultImport):

    def _runpy(self,*code):
        cmd = [sys.executable,"-c"]
        libpath = os.path.join(self.tdir,"library.zip")
        if not os.path.exists(libpath):
            self.zipit()
        bscode = "import sys; sys.path = [%s]; " % (repr(libpath),)
        for stmt in code:
            bscode += stmt + "; "
        cmd.append(bscode)
        p = subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        return p

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
                f.write("print 'RUNNING'\n")
                f.write("import signedimp.crypto.rsa\n")
                f.write("print 'SUCCESS'\n")
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
            p = subprocess.Popen(os.path.join(self.distdir,"script.exe"))
            self.assertEquals(p.wait(),0)

        def test_signed_app_succeeds(self):
            signedimp.tools.sign_py2exe_app(self.distdir)
            p = subprocess.Popen(os.path.join(self.distdir,"script.exe"))
            self.assertEquals(p.wait(),0)

        def test_unsigned_app_fails(self):
            signedimp.tools.sign_py2exe_app(self.distdir)
            zf = zipfile.ZipFile(os.path.join(self.distdir,"library.zip"),"a")
            zf.writestr(signedimp.HASHFILE_NAME,"")
            p = subprocess.Popen(os.path.join(self.distdir,"script.exe"))
            self.assertNotEquals(p.wait(),0)

        def test_modified_app_fails(self):
            signedimp.tools.sign_py2exe_app(self.distdir)
            zf = zipfile.ZipFile(os.path.join(self.distdir,"library.zip"),"a")
            zf.writestr("signedimp/crypto/__init__.py","")
            p = subprocess.Popen(os.path.join(self.distdir,"script.exe"))
            self.assertNotEquals(p.wait(),0)

        def test_unverified_modules_fails(self):
            signedimp.tools.sign_py2exe_app(self.distdir,check_modules=[])
            zf = zipfile.ZipFile(os.path.join(self.distdir,"library.zip"),"a")
            zf.writestr("signedimp/crypto/__init__.py","")
            p = subprocess.Popen(os.path.join(self.distdir,"script.exe"))
            self.assertNotEquals(p.wait(),0)

        def test_disabled_check_modules_succeeds(self):
            signedimp.tools.sign_py2exe_app(self.distdir,check_modules=False)
            p = subprocess.Popen(os.path.join(self.distdir,"script.exe"))
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


