"""Deprecated compatibility package — import :mod:`wombat_server` instead.

``wafpass_server`` was the module name before the WAF++ → Wombat rebrand. It
is kept as a thin alias for one migration window; imports emit a
:class:`DeprecationWarning`.
"""

from __future__ import annotations

import importlib
import importlib.abc
import importlib.util
import sys
import warnings

warnings.warn(
    "The 'wafpass_server' package is deprecated after the WAF++ → Wombat "
    "rebrand; import 'wombat_server' instead.",
    DeprecationWarning,
    stacklevel=2,
)

import wombat_server as _wombat_server  # noqa: E402

__version__ = _wombat_server.__version__


class _WombatAliasLoader(importlib.abc.Loader):
    """Load ``wafpass_server.<name>`` by copying the ``wombat_server.<name>`` module."""

    def create_module(self, spec):  # noqa: ANN001 - importlib protocol
        return None

    def exec_module(self, module) -> None:  # noqa: ANN001 - importlib protocol
        target_name = "wombat_server" + module.__name__[len("wafpass_server"):]
        target = importlib.import_module(target_name)
        module.__dict__.update(target.__dict__)
        module.__doc__ = target.__doc__


class _WombatAliasFinder(importlib.abc.MetaPathFinder):
    """Redirect every ``wafpass_server.*`` submodule import to ``wombat_server.*``."""

    def find_spec(self, fullname, path=None, target=None):  # noqa: ANN001
        if fullname.startswith("wafpass_server."):
            return importlib.util.spec_from_loader(fullname, _WombatAliasLoader())
        return None


sys.meta_path.insert(0, _WombatAliasFinder())
