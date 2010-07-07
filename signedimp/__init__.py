"""

signedimp:  signed imports for verified loading of python modules
=================================================================


This module implements a PEP-302-compatible import hook for verifying Python
modules before they are loaded, by means of cryptographically-signed hashes.
It's designed to compliment the code-signing functionality of your host OS,
which may be able to verify the Python executable itself but not the code
that is loaded dynamically at runtime.

It will mostly be useful for frozen Python applications, or other sitautions
where code is not expected to change.  It will be almost useless with a
standard Python interpreter.

To use, create a SignedImportManager with the appropriate keys and install
it into the import machinery as follows::

    from signedimp import SignedImportManager, RSAKeyWithPSS

    key = RSAKeyWithPSS(modulus,pub_exponent)
    mgr = SignedImportManager([key])
    mgr.install()

From this point on, all requests to import a module will be checked against
signed manifest files before being allow to proceed.  If a module cannot be
validated then the import will fail.

Validation is performed in coopertion with the existing import machinery,
using the optional loader methods get_code() and get_data().  It works with
at least the default import machinery and the zipimport module; if you have
custom import hooks that don't offer these optional methods that will not
be usabled with signedimp.


Manifests
---------

To verify imports, each entry on sys.path must contain a manifest file, which
contains a cryptographic hash for each module and is signed by one or more
private keys.  This file is called "signedimp-manifest.txt" and it will be
requested from each import loader using the get_data() method - in practice
this means that the file must exist in the root of each directory and each
zipfile listed on sys.path.

The manifest is a simple text file.  It begins with zero or more lines giving
a key fingerprint followed by a signature using that key; these are separated
from the hash data by a blank line.  It then contains a hash type identifier
and one line for each module hash.  Here's a short example::

      ----
      key1fingerprint signature1
      key2fingerprint signature2

      md5
      m 76f3f13442c26fd4f1c709c7b03c6b76 os
      m f56dbc5ee6774e857a7ef07accdbd19b hashlib
      d 43b74fc5d2acb6b4e417f4feff06dd81 some/data/file.txt
      ----
 
The file can contain hashes for different kinds of data; "m" indicates a module
hash while "d" indicates a generic data file.  The format of the fingerprint
and signature depend on the types of key being used.

To create a manifest file you will need a key object that includes the private
key data.  You can then use the functions in the "tools" submodule::

    key = RSAKeyWithPSS(modulus,pub_exponent,priv_exponent)
    signedimp.tools.sign_directory("some/dir/on/sys/path",key)
    signedimp.tools.sign_zipfile("some/zipfile/on/sys/path.zip",key)



Bootstrapping
-------------

Clearly there is a serious bootstrapping issue here - while we can verify
imports using this module, how do we verify the import of this module itself?
To be of any use, it must be incorporated as part of a signed executable.
There are several options:

   * include signedimp in a zipfile appended to the executable, and put the
     executable itself as the first item on sys.path.  Something like this::

       SCRIPT = '''
       import sys
       old_sys_path = sys.path
       sys.path = [sys.executable]
       from signedimport import SignedImportManager, RSAKeyWithPSS
       key = RSAKeyWithPSS(modulus,pub_exponent)
       SignedImportManager([key]).install()
       sys.path = old_sys_path

       actually_start_my_appliction()
       '''

   * use the signedimp.get_bootstrap_code() function to obtain code that can
     be included verbatim in your startup script, and embed the startup
     script in the executable.  Something like this::

       SCRIPT = '''
       %s
       key = RSAKeyWithPSS(modulus,pub_exponent)
       SignedImportManager([key]).install()
       
       actually_start_my_appliction()
       ''' % (signedimp.get_bootstrap_code(),)


Since the bootstrapping code can't perform any imports, everything (even the
cryptographic primitives) is implemented in pure Python by default.  It is
thus rather slow.  If you're able to securely bundle e.g. hashlib or PyCrypto
in the executable itself, import them *before* installing the signed import
manager so that it knows they are safe to use.

Of course, the first thing the import manager does once installed is try to
import these modules and speed up imports for the rest of the process.


Caveats
-------

All of the usual crypto caveats apply here.  I'm not a security expert.  The
system is only a safe as your private key, and as the operating system it's
run on.  In addition, there are some specific caveats for this module based on
the way it works.

This module operates by wrapping the existing import machinery.  To check the
hash of a module, it asks the appropriate loader object for the code of that
module, verifies the hash, then gives the loader the OK to import it.  It's
quite likely that the loader will re-read the data from disk when loading the
module, so there is a brief window in which it could be replaced by malicious
code.  I don't see any way to avoid this short of replacing all the existing
import machinery, which I'm not going to do.

As mentioned above, this module is useless if you load it from an untrusted
source.  You will need to sign your actual executable and you will need to
somehow bundle some signedimp bootstrapping code into it.  See the section
on "bootstrapping" for more details.

You must also be careful not to import anything before you have installed the
signed import manager.  (One exception is the "sys" module, which should always
be built into the executable itself and so safe to import.)

Finally, you may have noticated that I'm going against all sensible crypto
advice and rolling my own scheme from basic primitives such as RSA and SHA1.
It would be much better to depend on a third-party crypto library like keyczar,
however:

   * I want the verification code to be runnable as pure python without
     any third-party imports, to make it as easy to bootstrap as possible.

   * I've copied the signature scheme directly from PKCS#1 and it's broadly
     the same as that used by keyczar etc.  This is a very well understood
     signing protocol.

   * The signing code is supposed to be run offline, in a controlled setting
     with controlled inputs, so the risk of e.g. timing attacks is small.

   * The verifying code can't leak any info about the private key because
     it simply doesn't have any, so it can be as slow and sloppy and clunky
     as needed.

I am of course open to negotiation and expert advice on any of these points.

You have been warned.

"""

from signedimp.bootstrap import SignedImportManager, RSAKeyWithPSS


def get_bootstrap_code(indent=0):
    """Get sourcecode you can use for inline bootstrapping of signed imports.

    This function basically returns the source code for signedimp.bootstrap,
    with some cryptographic primatives forcibly inlined as pure python, and
    indented to the specified level.

    You would use it to boostrap signed imports in the startup script of your
    application, e.g. built a script like the following and hand it off to
    py2exe for freezing:

       SCRIPT = '''
       %s
       key = RSAKeyWithPSS(modulus,pub_exponent)
       SignedImportManager([key]).install()
       actually_start_my_appliction()
       ''' % (signedimp.get_bootstrap_code(),)

    """
    raise NotImplementedError

