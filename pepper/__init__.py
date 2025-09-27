"""
Pepper is a CLI front-end to salt-api
"""

from typing import Optional

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _version

from pepper.libpepper import Pepper
from pepper.exceptions import PepperException

__all__ = ("__version__", "Pepper", "PepperException")

__version__: Optional[str]
try:
    __version__ = _version("salt_pepper")
except PackageNotFoundError:
    # package is not installed
    __version__ = None

# For backwards compatibility
version: Optional[str] = __version__  # type: ignore[no-redef]
sha: Optional[str] = None
