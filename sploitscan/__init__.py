from __future__ import annotations

# Public package API and metadata

from .constants import VERSION as __version__
from .cli import cli, main

__all__ = [
    "__version__",
    "cli",
    "main",
]
