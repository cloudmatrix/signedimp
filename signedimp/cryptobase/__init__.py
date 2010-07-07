"""

  signedimp.cryptobase:  basic pure-python crypto primitives.

This package contains pure-python implementations of the crypto primatives
necessary for bootstrapping a signed import setup.  The MD5 and SHA1 modules
are taken from the PyPy project; the RSA-related modules are original.

Don't use anything from this module unless you know you really need it. Use
the signedimp.crypto module instead, which will use various third-party 
modules for much better performance.

"""

