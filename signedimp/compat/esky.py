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
        #  On OSX, the signature file may be within a bundled ".app" directory
        #  or in the top level of the target dir.
        if sys.platform == "darwin":
            if __esky_name__ is not None:
                signed_dir = pathjoin(target_dir,__esky_name__+".app")
                if not exists(pathjoin(signed_dir,signedimp.HASHFILE_NAME)):
                    signed_dir = target_dir
            else:
                for nm in listdir(target_dir):
                    if nm.endswith(".app"):
                        signed_dir = pathjoin(target_dir,nm)
                        if exists(pathjoin(signed_dir,signedimp.HASHFILE_NAME)):
                            break
                else:
                    signed_dir = target_dir
        else:
            signed_dir = target_dir
        loader = signedimp.DefaultImporter(signed_dir,signed_dir)
        loader = signedimp.SignedLoader(manager,loader)
        for target_exe in get_exe_locations(target_dir):
            #  Calling get_data forces verification of the specfied data file.
            try:
                loader.get_data(target_exe[len(signed_dir)+1:])
                break
            except EnvironmentError:
                pass
        orig_chainload(target_dir)
    return _chainload
_chainload = _make_signedimp_chainload(_chainload)
""" % locals()


