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
    signedimp_bootstrap = signedimp.tools.get_bootstrap_code()
    return """
def _make_signedimp_chainload(orig_chainload):
    %(signedimp_bootstrap)s
    key = %(key)r
    def chainload(target_dir):
        orig_chainload(target_dir)
    return chainload
chainload = _make_signedimp_chainload(chainload)
""" % locals()


