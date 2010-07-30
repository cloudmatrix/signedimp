#  Copyright (c) 2009-2010, Cloud Matrix Pty. Ltd.
#  All rights reserved; available under the terms of the BSD License.
"""

signedimp:  signed imports for verified loading of python modules
=================================================================


This module implements an import hook for verifying Python modules before they
are loaded, by means of cryptographically-signed hashes.  It is compatible with
PEP 302 and designed to complement the code-signing functionality of your host
OS (e.g. Microsoft Authenticode, Apple OSX Code Signing) which may be able to
verify the Python executable itself but not the code that is dynamically loaded
at runtime.

It will mostly be useful for frozen Python applications, or other situations
where code is not expected to change.  It will be almost useless with a
standard Python interpreter.

If you're just after a black-box solution, you could try one of the following
function calls to sign your app with a new randomly-generated key::

    signedimp.tools.sign_py2exe_app(path_to_app_dir)
    signedimp.tools.sign_py2app_bundle(path_to_app_dir)
    signedimp.tools.sign_cxfreeze_app(path_to_app_dir)

These functions modify a frozen Python application so that it verifies the
integrity of its modules before they are loaded, using a one-time key generated
just for that application.

But really, you should read on to understand exactly what's going on.  There
are plenty of caveats to be had.


Enabling Signed Imports
-----------------------

To enable signed imports, you need to create a SignedImportManager with the
appropriate cryptographic keys and install it into the import machinery::

    from signedimp import SignedImportManager, RSAKeyWithPSS

    key = RSAKeyWithPSS(modulus,pub_exponent)
    mgr = SignedImportManager([key])
    mgr.install()

From this point on, all requests to import a module will be checked against
signed manifest files before being allow to proceed.  If a module cannot be
verified then the import will fail.

Verification is performed in coopertion with the existing import machinery,
using the optional loader method get_data().  It works with at least the 
default import machinery and the zipimport module; if you have custom import
hooks that don't offer this method, or that don't conform to the standard
file layout for python imports, they will will not be usable with signedimp.


Keys
----

Currently signedimp uses RSA keys for its digital signatures, along with the
"Probabilistic Signature Scheme" padding mechanism.  To generate a new key
you will need PyCrypto installed, and to do the following::

    from signedimp.crypto.rsa import RSAKeyWithPSS
    key = RSAKeyWithPSS.generate()
    pubkey = key.get_public_key()

Store this key somewhere safe, you'll need it to sign files.  The simplest way
is using the "save_to_file" method::

    with open("mykeyfile","wb") as f:
        key.save_to_file(f,"mypassword")

To retreive the key in e.g. your build scripts, do something like this::

    with open("mykeyfile","rb") as f:
        key = RSAKeyWithPSS.load_from_file(f,getpass())

You'll also need to embed the public key somewhere in your final executable
so it's available for verifying imports.  The functions in signedimp.tools will
do this for you - if you're writing you own scheme you can either pickle it, or
embed its repr() somewhere in your source code.


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
      key1fingerprint b64-encoded-signature1
      key2fingerprint b64-encoded-signature2

      md5
      m 76f3f13442c26fd4f1c709c7b03c6b76 os
      m f56dbc5ee6774e857a7ef07accdbd19b hashlib
      d 43b74fc5d2acb6b4e417f4feff06dd81 some/data/file.txt
      ----
 
The file can contain hashes for different kinds of data; "m" indicates a module
hash while "d" indicates a generic data file.  The format of the fingerprint
and signature depend on the types of key being used, and should be treated as
ASCII blobs.

To create a manifest file you will need a key object that includes the private
key data.  You can then use the functions in the "tools" submodule::

    key = RSAKeyWithPSS(modulus,pub_exponent,priv_exponent)

    signedimp.tools.sign_directory("some/dir/on/sys/path",key)
    signedimp.tools.sign_zipfile("some/zipfile/on/sys/path.zip",key)


Bootstrapping
-------------

Clearly there is a serious bootstrapping issue when using this module - while
we can verify imports one this module is loaded, how do we verify the import of
this module itself? To be of any use, it must be incorporated as part of a
signed executable. There are several options:

   * include signedimp as a "frozen" module in the Python interpreter itself,
     by mucking with the PyImport_FrozenModules pointer.

   * include signedimp in a zipfile appended to the executable, and put the
     executable itself as the first item on sys.path.

   * use the signedimp.tools.get_bootstrap_code() function to obtain code that
     can be included verbatim in your startup script, and embed the startup
     script in the executable.

Since the bootstrapping code can't perform any imports, everything (even the
cryptographic primitives) is implemented in pure Python by default.  It is
thus rather slow.  If you're able to securely bundle e.g. hashlib or PyCrypto
in the executable itself, import them before* installing the signed import
manager so that it knows they are safe to use.

Of course, the first thing the import manager does once installed is try to
import these modules and speed up imports for the rest of the process.

A word of caution - most freezer programs (e.g. py2exe or bbfreeze) execute
their own startup scripts before running the user-supplied script, and these
startup scripts often import common modules such as "os".  You'll either need
to hack the frozen exe to run the signedimp bootstrapping code first, or
securely bundle these modules into the executable itself.

So far I've worked out the necessary incantations for signing py2exe, py2app
and cxfreeze applications, and there are helper functions in "signedimp.tools"
that will do it for you.

I don't belive it's possible to sign a bbfreeze application without patching
bbfreeze itsel.  Since bbfreeze always sets sys.path to the library.zip and
the application dir, there is no way to bundle the bootstrapping code into
the executable itself.


Caveats
-------

All of the usual crypto caveats apply here.  I'm not a security expert.  The
system is only a safe as your private key, as the signature on the main python
executable, and as the operating system it's run on.  In addition, there are
some specific caveats for this module based on the way it works.

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
     the same as that used by keyczar etc.  This is a very simple and well
     understood signing protocol.

   * The signing code is supposed to be run offline, in a controlled setting
     with controlled inputs, so the risk of e.g. timing attacks is small.

   * The verifying code can't leak any info about the private key because
     it simply doesn't have any, so it can be as slow and sloppy and clunky
     as needed.

I am of course open to negotiation and expert advice on any of these points.

You have been warned.

"""

__ver_major__ = 0
__ver_minor__ = 1
__ver_patch__ = 5
__ver_sub__ = ""
__ver_tuple__ = (__ver_major__,__ver_minor__,__ver_patch__,__ver_sub__)
__version__ = "%d.%d.%d%s" % __ver_tuple__


from signedimp.bootstrap import *

#  This indicates whether signedimp.__path__ can be trusted for finding
#  submodules of this package.  It will be broken if signedimp is created
#  by some bootstrapping code rather than a traditional import.
_path_is_broken = False


