"""
Authentik Identity Provider Management.
High-level wrapper around authentik-client for managing users, groups, applications, and providers.
"""
import logging
from typing import List, Dict, Any, Optional
import requests

logger = logging.getLogger(__name__)

class AuthentikClient:
    """
    High-level Authentik API client.
    Provides simplified methods for common identity management tasks.
    """
    def __init__(self, base_url: str, api_token: str, verify_ssl: bool = True):
        """
        Initialize Authentik client.
        
        Args:
            base_url: Authentik instance URL (e.g., https://auth.example.com)
            api_token: API token with appropriate permissions
            verify_ssl: Whether to verify SSL certificates
        """
        self.base_url = base_url.rstrip("/")
        self.api_token = api_token
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        })
        self.session.verify = verify_ssl

    def _request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make an API request."""
        url = f"{self.base_url}/api/v3/{endpoint.lstrip('/')}"
        logger.debug(f"Authentik API: {method} {url}")
        
        response = self.session.request(method, url, **kwargs)
        response.raise_for_status()
        
        if response.content:
            return response.json()
        return {}

    # ==================== USERS ====================
    
    def list_users(self, search: str = None) -> List[Dict[str, Any]]:
        """List all users, optionally filtered by search term."""
        params = {}
        if search:
            params["search"] = search
        result = self._request("GET", "/core/users/", params=params)
        return result.get("results", [])

    def get_user(self, user_id: int) -> Dict[str, Any]:
        """Get a specific user by ID."""
        return self._request("GET", f"/core/users/{user_id}/")

    def create_user(
        self, 
        username: str, 
        name: str, 
        email: str = None,
        is_active: bool = True,
        groups: List[str] = None,
        attributes: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Create a new user.
        
        Args:
            username: Unique username
            name: Display name
            email: Email address
            is_active: Whether user is active
            groups: List of group UUIDs to add user to
            attributes: Custom attributes dict
        """
        data = {
            "username": username,
            "name": name,
            "is_active": is_active,
        }
        if email:
            data["email"] = email
        if groups:
            data["groups"] = groups
        if attributes:
            data["attributes"] = attributes
            
        logger.info(f"Creating Authentik user: {username}")
        return self._request("POST", "/core/users/", json=data)

    def update_user(self, user_id: int, **kwargs) -> Dict[str, Any]:
        """Update a user's attributes."""
        logger.info(f"Updating Authentik user: {user_id}")
        return self._request("PATCH", f"/core/users/{user_id}/", json=kwargs)

    def delete_user(self, user_id: int):
        """Delete a user."""
        logger.info(f"Deleting Authentik user: {user_id}")
        self._request("DELETE", f"/core/users/{user_id}/")

    def set_user_password(self, user_id: int, password: str):
        """Set a user's password."""
        logger.info(f"Setting password for user: {user_id}")
        self._request("POST", f"/core/users/{user_id}/set_password/", json={"password": password})

    # ==================== GROUPS ====================

    def list_groups(self, search: str = None) -> List[Dict[str, Any]]:
        """List all groups."""
        params = {}
        if search:
            params["search"] = search
        result = self._request("GET", "/core/groups/", params=params)
        return result.get("results", [])

    def get_group(self, group_id: str) -> Dict[str, Any]:
        """Get a specific group by UUID."""
        return self._request("GET", f"/core/groups/{group_id}/")

    def create_group(
        self, 
        name: str, 
        is_superuser: bool = False,
        parent: str = None,
        attributes: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Create a new group."""
        data = {
            "name": name,
            "is_superuser": is_superuser,
        }
        if parent:
            data["parent"] = parent
        if attributes:
            data["attributes"] = attributes
            
        logger.info(f"Creating Authentik group: {name}")
        return self._request("POST", "/core/groups/", json=data)

    def delete_group(self, group_id: str):
        """Delete a group."""
        logger.info(f"Deleting Authentik group: {group_id}")
        self._request("DELETE", f"/core/groups/{group_id}/")

    def add_user_to_group(self, user_id: int, group_id: str):
        """Add a user to a group."""
        user = self.get_user(user_id)
        groups = user.get("groups", [])
        if group_id not in groups:
            groups.append(group_id)
            self.update_user(user_id, groups=groups)
            logger.info(f"Added user {user_id} to group {group_id}")

    def remove_user_from_group(self, user_id: int, group_id: str):
        """Remove a user from a group."""
        user = self.get_user(user_id)
        groups = user.get("groups", [])
        if group_id in groups:
            groups.remove(group_id)
            self.update_user(user_id, groups=groups)
            logger.info(f"Removed user {user_id} from group {group_id}")

    # ==================== APPLICATIONS ====================

    def list_applications(self) -> List[Dict[str, Any]]:
        """List all applications."""
        result = self._request("GET", "/core/applications/")
        return result.get("results", [])

    def get_application(self, slug: str) -> Dict[str, Any]:
        """Get an application by slug."""
        return self._request("GET", f"/core/applications/{slug}/")

    def create_application(
        self,
        name: str,
        slug: str,
        provider: int = None,
        meta_launch_url: str = None,
        open_in_new_tab: bool = False
    ) -> Dict[str, Any]:
        """Create a new application."""
        data = {
            "name": name,
            "slug": slug,
            "open_in_new_tab": open_in_new_tab,
        }
        if provider:
            data["provider"] = provider
        if meta_launch_url:
            data["meta_launch_url"] = meta_launch_url
            
        logger.info(f"Creating Authentik application: {name}")
        return self._request("POST", "/core/applications/", json=data)

    def delete_application(self, slug: str):
        """Delete an application."""
        logger.info(f"Deleting Authentik application: {slug}")
        self._request("DELETE", f"/core/applications/{slug}/")

    # ==================== PROVIDERS ====================

    def list_providers(self, provider_type: str = None) -> List[Dict[str, Any]]:
        """
        List providers.
        
        Args:
            provider_type: Filter by type (oauth2, saml, proxy, ldap, etc.)
        """
        if provider_type:
            endpoint = f"/providers/{provider_type}/"
        else:
            endpoint = "/providers/all/"
        result = self._request("GET", endpoint)
        return result.get("results", [])

    def create_oauth2_provider(
        self,
        name: str,
        authorization_flow: str,
        client_type: str = "confidential",
        client_id: str = None,
        client_secret: str = None,
        redirect_uris: str = None
    ) -> Dict[str, Any]:
        """Create an OAuth2 provider."""
        data = {
            "name": name,
            "authorization_flow": authorization_flow,
            "client_type": client_type,
        }
        if client_id:
            data["client_id"] = client_id
        if client_secret:
            data["client_secret"] = client_secret
        if redirect_uris:
            data["redirect_uris"] = redirect_uris
            
        logger.info(f"Creating OAuth2 provider: {name}")
        return self._request("POST", "/providers/oauth2/", json=data)

    def create_proxy_provider(
        self,
        name: str,
        authorization_flow: str,
        external_host: str,
        mode: str = "forward_single"
    ) -> Dict[str, Any]:
        """Create a proxy provider for forward auth."""
        data = {
            "name": name,
            "authorization_flow": authorization_flow,
            "external_host": external_host,
            "mode": mode,
        }
        logger.info(f"Creating proxy provider: {name}")
        return self._request("POST", "/providers/proxy/", json=data)

    # ==================== FLOWS ====================

    def list_flows(self) -> List[Dict[str, Any]]:
        """List all flows."""
        result = self._request("GET", "/flows/instances/")
        return result.get("results", [])

    def get_flow(self, slug: str) -> Dict[str, Any]:
        """Get a flow by slug."""
        return self._request("GET", f"/flows/instances/{slug}/")

    # ==================== TOKENS ====================

    def list_tokens(self, user_id: int = None) -> List[Dict[str, Any]]:
        """List API tokens, optionally filtered by user."""
        params = {}
        if user_id:
            params["user"] = user_id
        result = self._request("GET", "/core/tokens/", params=params)
        return result.get("results", [])

    def create_token(
        self,
        identifier: str,
        user: int,
        intent: str = "api",
        expiring: bool = True,
        description: str = None
    ) -> Dict[str, Any]:
        """Create an API token for a user."""
        data = {
            "identifier": identifier,
            "user": user,
            "intent": intent,
            "expiring": expiring,
        }
        if description:
            data["description"] = description
            
        logger.info(f"Creating token: {identifier}")
        return self._request("POST", "/core/tokens/", json=data)

    # ==================== HEALTH/META ====================

    def health_check(self) -> bool:
        """Check if Authentik is healthy."""
        try:
            self._request("GET", "/root/config/")
            return True
        except Exception:
            return False

    def get_system_info(self) -> Dict[str, Any]:
        """Get system information."""
        return self._request("GET", "/admin/system/")
