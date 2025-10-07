#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

try:
    from .cli import cli
except Exception:
    # If run as a script from inside the "sploitscan" directory, add the project root to sys.path
    import os
    import sys
    pkg_dir = os.path.dirname(os.path.abspath(__file__))         # .../SploitScan/sploitscan
    project_root = os.path.dirname(pkg_dir)                      # .../SploitScan
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    from sploitscan.cli import cli

if __name__ == "__main__":
    cli()
