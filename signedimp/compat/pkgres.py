"""

  signedimp.compat.pkgres:  pkg_resources support code for signedimp

This module contains support for using signedimp together with the
setuptools/pkg_resources modules.  It doesn't export anything interesting,
just registers some helper functions with the pkg_resources machinery.

You must import this module before using pkg_resources when signed imports
are in use.

"""

import pkg_resources
import signedimp

_find_adapter = pkg_resources._find_adapter
_provider_factories = pkg_resources._provider_factories
DefaultProvider  = pkg_resources.DefaultProvider

import sys
print >>sys.stderr, "REGISTERING SIGNEDIMP WITH PKGRES", pkg_resources

def _get_provider(mod):
    """Get the pkg_resources provider appropriate for the given loader.

    This basically calls back into the pkg_resources machinery to find the
    provider for the wrapper loader, and just returns that.
    """
    return _find_adapter(_provider_factories,mod.__loader__.loader)(mod)

pkg_resources.register_loader_type(signedimp.SignedLoader,_get_provider)
pkg_resources.register_loader_type(signedimp.DefaultImporter,DefaultProvider)

print >>sys.stderr, "PROVIDERS NOW", _provider_factories


