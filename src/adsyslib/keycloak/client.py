"""
Keycloak Identity Provider Client.
Basic client for extracting data from Keycloak for migration purposes.
"""

import logging
from typing import Any, Optional
from urllib.parse import quote

import requests

from adsyslib.http import APIError, request, validate_url

logger = logging.getLogger(__name__)


class KeycloakClient:
    """
    Basic Keycloak client focused on data extraction for migration.
    Uses Keycloak Admin REST API.
    """

    def __init__(
        self,
        base_url: str,
        realm: str = "master",
        client_id: str = "admin-cli",
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_ssl: bool = True,
        timeout: float = 30.0,
        auth_realm: str = "master",
    ):
        """
        Initialize Keycloak client.

        Args:
            base_url: Keycloak base URL (e.g., https://auth.example.com)
            realm: Realm to work with
            client_id: Client ID for authentication
            username: Admin username
            password: Admin password
            verify_ssl: Whether to verify SSL certificates
        """
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.timeout = timeout
        self.auth_realm = auth_realm
        self.base_url = validate_url(base_url)
        self.realm = realm
        self.client_id = client_id
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.token = None

        if username and password:
            self._authenticate()

    def _authenticate(self) -> None:
        """Authenticate and get access token."""
        url = f"{self.base_url}/realms/{quote(self.auth_realm, safe='')}/protocol/openid-connect/token"
        data = {
            "client_id": self.client_id,
            "username": self.username,
            "password": self.password,
            "grant_type": "password",
        }

        logger.debug("Authenticating to Keycloak")
        data = request(self.session, "POST", url, self.timeout, data=data)
        if not data.get("access_token"):
            raise APIError("Authentication response has no access token")
        self.token = data["access_token"]
        self.session.headers.update({"Authorization": f"Bearer {self.token}"})

    def _request(self, method: str, endpoint: str, **kwargs: Any) -> Any:
        """Make an authenticated API request."""
        url = f"{self.base_url}/admin/realms/{quote(self.realm, safe='')}/{endpoint.lstrip('/')}"
        logger.debug(f"Keycloak API: {method} {url}")

        return request(self.session, method, url, self.timeout, **kwargs)

    def close(self) -> None:
        self.session.close()

    def __enter__(self) -> "KeycloakClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def iter_users(self, page_size: int = 100) -> Any:
        """Yield users page by page without truncating realm exports."""
        if page_size <= 0:
            raise ValueError("page_size must be positive")
        offset = 0
        seen = set()
        while True:
            users = self._request("GET", "users", params={"first": offset, "max": page_size})
            if not isinstance(users, list):
                raise APIError("Invalid user page")
            if not users:
                return
            for user in users:
                identity = user.get("id")
                if not identity or identity in seen:
                    raise APIError("User pagination returned a missing or repeated ID")
                seen.add(identity)
                yield user
            offset += len(users)

    # ==================== REALM OPERATIONS ====================

    def get_realm(self) -> dict[str, Any]:
        """Get current realm configuration."""
        return self._request("GET", "")

    def list_realms(self) -> list[dict[str, Any]]:
        """List all realms (requires master realm access)."""
        url = f"{self.base_url}/admin/realms"
        self.session.headers.update({"Authorization": f"Bearer {self.token}"})
        return request(self.session, "GET", url, self.timeout)

    # ==================== USER OPERATIONS ====================

    def list_users(
        self, max_results: int = 100, search: Optional[str] = None
    ) -> list[dict[str, Any]]:
        """
        List users in the realm.

        Args:
            max_results: Maximum number of users to return
            search: Optional search term

        Returns:
            List of user dictionaries
        """
        if max_results <= 0:
            raise ValueError("max_results must be positive")
        params: dict[str, Any] = {"max": max_results}
        if search:
            params["search"] = search

        return self._request("GET", "users", params=params)

    def get_user(self, user_id: str) -> dict[str, Any]:
        """Get a specific user by ID."""
        return self._request("GET", f"users/{user_id}")

    def get_user_by_username(self, username: str) -> Optional[dict[str, Any]]:
        """Get a user by username."""
        users = self._request("GET", "users", params={"username": username, "exact": True})
        return users[0] if users else None

    def get_user_groups(self, user_id: str) -> list[dict[str, Any]]:
        """Get groups for a specific user."""
        return self._request("GET", f"users/{user_id}/groups")

    def get_user_roles(self, user_id: str) -> dict[str, Any]:
        """Get role mappings for a user."""
        return self._request("GET", f"users/{user_id}/role-mappings")

    def get_user_credentials(self, user_id: str) -> list[dict[str, Any]]:
        """Get credentials for a user (metadata only, not passwords)."""
        return self._request("GET", f"users/{user_id}/credentials")

    # ==================== GROUP OPERATIONS ====================

    def list_groups(self) -> list[dict[str, Any]]:
        """List all groups in the realm."""
        return self._request("GET", "groups")

    def get_group(self, group_id: str) -> dict[str, Any]:
        """Get a specific group by ID."""
        return self._request("GET", f"groups/{group_id}")

    def get_group_members(self, group_id: str) -> list[dict[str, Any]]:
        """Get members of a group."""
        return self._request("GET", f"groups/{group_id}/members")

    # ==================== CLIENT OPERATIONS ====================

    def list_clients(self) -> list[dict[str, Any]]:
        """List all clients in the realm."""
        return self._request("GET", "clients")

    def get_client(self, client_id: str) -> dict[str, Any]:
        """Get a specific client by ID."""
        return self._request("GET", f"clients/{client_id}")

    def get_client_by_client_id(self, client_id: str) -> Optional[dict[str, Any]]:
        """Get a client by clientId."""
        clients = self._request("GET", "clients", params={"clientId": client_id})
        return clients[0] if clients else None

    # ==================== ROLE OPERATIONS ====================

    def list_realm_roles(self) -> list[dict[str, Any]]:
        """List all realm-level roles."""
        return self._request("GET", "roles")

    def get_realm_role(self, role_name: str) -> dict[str, Any]:
        """Get a specific realm role."""
        return self._request("GET", f"roles/{role_name}")

    def list_client_roles(self, client_id: str) -> list[dict[str, Any]]:
        """List roles for a specific client."""
        return self._request("GET", f"clients/{client_id}/roles")

    # ==================== EXPORT/MIGRATION HELPERS ====================

    def export_realm_full(self) -> dict[str, Any]:
        """
        Export complete realm configuration including users.
        Note: This is a convenience method that aggregates multiple API calls.

        Returns:
            Dictionary containing realm, users, groups, clients, roles
        """
        logger.info(f"Exporting realm: {self.realm}")

        export_data: dict[str, Any] = {
            "realm": self.get_realm(),
            "users": [],
            "groups": self.list_groups(),
            "clients": self.list_clients(),
            "roles": self.list_realm_roles(),
        }

        # Export all users with their details
        users = self.iter_users()
        for user in users:
            user_id = user["id"]
            user_full = {
                **user,
                "groups": self.get_user_groups(user_id),
                "role_mappings": self.get_user_roles(user_id),
                "credentials_metadata": self.get_user_credentials(user_id),
            }
            export_data["users"].append(user_full)

        logger.info(
            f"Exported {len(export_data['users'])} users, "
            f"{len(export_data['groups'])} groups, "
            f"{len(export_data['clients'])} clients"
        )

        return export_data

    def export_users_minimal(self) -> list[dict[str, Any]]:
        """
        Export users with essential fields for migration.

        Returns:
            List of user dictionaries with migration-ready fields
        """
        users = self.iter_users()
        minimal_users = []

        for user in users:
            user_id = user["id"]
            groups = self.get_user_groups(user_id)

            minimal_user = {
                "username": user.get("username"),
                "email": user.get("email"),
                "firstName": user.get("firstName"),
                "lastName": user.get("lastName"),
                "enabled": user.get("enabled", True),
                "emailVerified": user.get("emailVerified", False),
                "attributes": user.get("attributes", {}),
                "groups": [g["name"] for g in groups],
                "created_timestamp": user.get("createdTimestamp"),
            }
            minimal_users.append(minimal_user)

        return minimal_users
