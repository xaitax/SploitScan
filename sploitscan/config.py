"""
Configuration loading and normalization for SploitScan.

- Discovers config.json from multiple standard locations
- Supports environment override via SPLOITSCAN_CONFIG_PATH
- Normalizes legacy key names (e.g., google_api_key -> google_ai_api_key)
- Returns a plain dict for compatibility with existing code paths
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional, Tuple


_DEFAULT_CONFIG: Dict[str, Any] = {
    "vulncheck_api_key": None,
    "openai_api_key": None,
    "google_ai_api_key": None,
    "grok_api_key": None,
    "deepseek_api_key": None,
    "local_database_dir": None,
}


def _debug_print(enabled: bool, msg: str) -> None:
    if enabled:
        print(msg)


def _candidate_config_paths(explicit_path: Optional[str]) -> Tuple[str, ...]:
    paths = []
    if explicit_path:
        paths.append(explicit_path)

    env_path = os.getenv("SPLOITSCAN_CONFIG_PATH")
    if env_path:
        paths.append(env_path)

    # Module directory default: sploitscan/config.json if shipped within package
    module_dir = os.path.dirname(os.path.abspath(__file__))
    paths.append(os.path.join(module_dir, "config.json"))

    # User-level defaults
    paths.extend(
        [
            os.path.expanduser("~/.sploitscan/config.json"),
            os.path.expanduser("~/.config/sploitscan/config.json"),
            os.path.expanduser("~/Library/Application Support/sploitscan/config.json"),  # macOS
            os.path.join(os.getenv("APPDATA", ""), "sploitscan", "config.json"),  # Windows
            "/etc/sploitscan/config.json",
        ]
    )
    # Remove empties / duplicates, preserve order
    seen = set()
    uniq = []
    for p in paths:
        if p and p not in seen:
            uniq.append(p)
            seen.add(p)
    return tuple(uniq)


def _normalize_keys(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize legacy or alternative keys to modern schema:
    - google_api_key -> google_ai_api_key
    """
    norm = dict(cfg)
    if "google_ai_api_key" not in norm and "google_api_key" in norm:
        norm["google_ai_api_key"] = norm.get("google_api_key")
    return norm


def _merge_with_defaults(cfg: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(_DEFAULT_CONFIG)
    merged.update(cfg or {})
    return merged


def load_config(config_path: Optional[str] = None, debug: bool = False) -> Dict[str, Any]:
    """
    Load configuration as a dict with standardized keys and defaults applied.

    Search order:
      1) Explicit --config path if provided
      2) SPLOITSCAN_CONFIG_PATH env var
      3) sploitscan/config.json (within package directory)
      4) ~/.sploitscan/config.json
      5) ~/.config/sploitscan/config.json
      6) ~/Library/Application Support/sploitscan/config.json (macOS)
      7) %APPDATA%/sploitscan/config.json (Windows)
      8) /etc/sploitscan/config.json

    Returns:
      dict: merged configuration with defaults and normalized keys.
    """
    for path in _candidate_config_paths(config_path):
        if os.path.isfile(path):
            _debug_print(debug, f"Trying config file: {path}")
            try:
                with open(path, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                _debug_print(debug, f"Successfully loaded config file: {path}")
                cfg = _normalize_keys(cfg)
                return _merge_with_defaults(cfg)
            except json.JSONDecodeError as e:
                print(f"⚠️ JSON parsing error in {path}: {e}")
            except Exception as e:
                print(f"⚠️ Unexpected error reading {path}: {e}")

    print("⚠️ Config file not found in any checked locations, using default settings.")
    return dict(_DEFAULT_CONFIG)


def get(key: str, default: Any = None, *, config: Optional[Dict[str, Any]] = None) -> Any:
    """
    Helper to retrieve a value from an explicitly passed config or the environment-driven defaults.

    Prefer passing the config returned by load_config() through your call chain.
    """
    if config is None:
        # Fall back to defaults without file lookup to avoid repeated IO.
        return _DEFAULT_CONFIG.get(key, default)
    return config.get(key, default)
