"""
Authentik Identity Provider Management.
"""
from adsyslib.authentik.client import AuthentikClient
from adsyslib.authentik.oauth import (
    AuthentikOAuthManager,
    OAuthProviderConfig,
    generate_env_file,
    load_providers_from_json,
)

__all__ = [
    "AuthentikClient",
    "AuthentikOAuthManager",
    "OAuthProviderConfig",
    "load_providers_from_json",
    "generate_env_file"
]
