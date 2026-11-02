from importlib.metadata import PackageNotFoundError, version as _pkg_version

try:
    __version__ = _pkg_version("wombat-server")
except PackageNotFoundError:
    try:
        # Deprecated: published as wafpass-server before the rebrand.
        __version__ = _pkg_version("wafpass-server")
    except PackageNotFoundError:
        __version__ = "1.2.0"
