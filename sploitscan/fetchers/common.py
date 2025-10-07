"""
Shared HTTP fetching utilities with consistent (data, error) return semantics.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple, Union, Iterable
import requests


DEFAULT_TIMEOUT = 30


def fetch(
    url: str,
    *,
    params: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> Tuple[Optional[requests.Response], Optional[str]]:
    """
    Perform an HTTP GET with a timeout.
    Returns (response, None) on success or (None, error_message) on failure.
    """
    try:
        resp = requests.get(url, params=params, headers=headers, timeout=timeout)
        resp.raise_for_status()
        return resp, None
    except requests.exceptions.RequestException as e:
        return None, f"❌ Error fetching data from {url}: {e}"


def fetch_json(
    url: str,
    *,
    params: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> Tuple[Optional[Union[Dict[str, Any], Any]], Optional[str]]:
    """
    Fetch an endpoint and parse JSON body.
    Returns (json_object, None) on success or (None, error_message) on failure.
    """
    resp, err = fetch(url, params=params, headers=headers, timeout=timeout)
    if err:
        return None, err
    try:
        return resp.json(), None  # type: ignore[return-value]
    except ValueError as e:
        return None, f"❌ Error parsing JSON data from {url}: {e}"


def iter_json_lines(
    url: str,
    *,
    params: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = DEFAULT_TIMEOUT,
    chunk_size: int = 8192,
) -> Tuple[Optional[Iterable[str]], Optional[str]]:
    """
    Stream an endpoint that serves line-delimited JSON (NDJSON).
    Returns (iterator_of_lines, None) or (None, error_message).
    """
    try:
        with requests.get(url, params=params, headers=headers, timeout=timeout, stream=True) as resp:
            resp.raise_for_status()
            def _line_iter():
                for raw in resp.iter_lines(chunk_size=chunk_size):
                    if raw:
                        yield raw.decode("utf-8")
            return _line_iter(), None
    except requests.exceptions.RequestException as e:
        return None, f"❌ Error streaming data from {url}: {e}"
