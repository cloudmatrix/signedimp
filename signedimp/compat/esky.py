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
def _make_signedimp_chainload(orig_chainload):
    %(signedimp_bootstrap)s
    def _chainload(target_dir):
        key = signedimp.%(pubkey)r
        manager = signedimp.SignedImportManager([key])
        target_exe = pathjoin(target_dir,basename(sys.executable))
        target_imp = signedimp.DefaultImporter(target_dir,target_dir)
        target_imp = signedimp.SignedLoader(manager,target_imp)
        #  Calling get_data forces verification of the specfied data file
        target_imp.get_data(basename(sys.executable))
        orig_chainload(target_dir)
    return _chainload
_chainload = _make_signedimp_chainload(_chainload)
""" % locals()


