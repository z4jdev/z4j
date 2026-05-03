"""z4j - the z4j server, API, and dashboard host.

Part of the z4j monorepo. Licensed under **AGPL v3**.

If you are an organization whose policy forbids AGPL-licensed code, a
commercial license is available - contact licensing@z4j.com.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version as _pkg_version

# Read the wheel version from installed metadata. The brain code
# ships in the ``z4j`` distribution as of the 1.4.0 consolidation
# cut (pre-1.4.0 it shipped in ``z4j-brain``; the brain shim still
# exists at the ``z4j-brain`` PyPI name but is metadata-only). We
# look up ``z4j`` because that's the actual wheel that delivers
# this code.
#
# The wire-protocol version is still exposed (for compat checks
# against agents) as ``protocol_version`` below, just under a
# different name so operator-facing surfaces (logs, banners,
# /api/v1/health) report the brain wheel version.
try:
    __version__ = _pkg_version("z4j")
except PackageNotFoundError:
    # Editable installs and source checkouts that haven't been
    # ``pip install -e .``'d won't have package metadata. Fall back
    # to the legacy z4j-brain dist (still installed by some test
    # paths) and then to the protocol version.
    try:
        __version__ = _pkg_version("z4j-brain")
    except PackageNotFoundError:
        from z4j_core.version import __version__  # type: ignore[no-redef]

from z4j_core.version import __version__ as protocol_version

__all__ = ["__version__", "protocol_version"]
