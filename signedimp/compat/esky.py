"""

  signedimp.compat.esky:  esky integration support code for signedimp

This module contains support for using signedimp together with the "esky"
auto-update module.  Use the "get_bootstrap_code" function to get code for
a custom chainloading function, which will verify the chainloaded exe before
executing it.  This code should be passed in to bdist_esky as part of the
"bootstrap_code" option.

"""

import signedimp.tools

def get_bootstrap_code(key):
    signedimp_bootstrap = signedimp.tools.get_bootstrap_code(indent="    ")
    pubkey = key.get_public_key()
    return """
def _make_signedimp_verify(orig_verify):
    %(signedimp_bootstrap)s
    key = signedimp.%(pubkey)r
    manager = signedimp.SignedImportManager([key])
    manager.install()
    def verify(target_file):
        orig_verify(target_file)
        manager._verify_file(target_file)
    return verify
verify = _make_signedimp_verify(verify)
""" % locals()


