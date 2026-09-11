"""Bounded, non-redirecting HTTP transport for authenticated identity clients."""

from typing import Any
from urllib.parse import urlsplit

import requests

from adsyslib.core import AdsysError


class APIError(AdsysError):
    """An identity request failed. Response bodies may contain secrets and are omitted."""


def validate_url(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("base_url must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("base_url must not contain credentials, a query, or a fragment")
    return url.rstrip("/")


def request(session: requests.Session, method: str, url: str, timeout: float, **kwargs: Any) -> Any:
    """Return decoded JSON; refuse redirects and never retry writes implicitly."""
    kwargs.setdefault("timeout", timeout)
    kwargs["allow_redirects"] = False
    try:
        response = session.request(method, url, **kwargs)
        if 300 <= response.status_code < 400:
            raise APIError("Identity API redirect refused; configure the canonical base URL")
        response.raise_for_status()
        if not response.content:
            return {}
        return response.json()
    except (requests.RequestException, ValueError) as exc:
        status = getattr(getattr(exc, "response", None), "status_code", None)
        raise APIError(
            f"Identity API request failed ({'HTTP ' + str(status) if status else type(exc).__name__})"
        ) from None
