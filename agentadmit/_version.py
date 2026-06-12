"""Single source of truth for the SDK version.

The version is read from the installed package metadata (which comes from
pyproject.toml at build time), so bumping pyproject.toml is the only step a
release needs — __version__ and the discovery document can never drift again.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("agentadmit")
except PackageNotFoundError:
    # Source checkout that was never pip-installed: report an honest
    # placeholder rather than masquerading as a real release.
    __version__ = "0.0.0.dev0"
