"""
OAuth Provider Management for Authentik.
High-level interface for managing OAuth2/OIDC providers using Django ORM direct access.

This module provides the same functionality as the custom CLI tool built for AfterDark,
but packaged as a reusable Python library.
"""
import json
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class OAuthProviderConfig:
    """Configuration for an OAuth2 provider."""
    app_name: str
    app_slug: str
    client_id: str
    redirect_uris: List[str]
    launch_url: str
    client_type: str = "confidential"  # or "public"
    description: Optional[str] = None
    port: Optional[int] = None


class AuthentikOAuthManager:
    """
    Manages OAuth2 providers via Django ORM direct access.

    This bypasses the Authentik API (which has permission issues) and uses
    Django ORM directly, similar to how Authentik's own admin interface works.

    Usage:
        # Via Docker exec
        manager = AuthentikOAuthManager(container_name="authentik-server")

        # Create a provider
        config = OAuthProviderConfig(
            app_name="My App",
            app_slug="my-app",
            client_id="my-app-client",
            redirect_uris=["http://localhost:3000/callback"],
            launch_url="http://localhost:3000/",
            client_type="confidential"
        )
        result = manager.create_provider(config)
        print(f"Client Secret: {result['client_secret']}")
    """

    def __init__(self, container_name: str = "authentik-server-prod"):
        """
        Initialize OAuth manager.

        Args:
            container_name: Docker container running Authentik
        """
        self.container_name = container_name

    def _docker_exec_python(self, script: str) -> Dict[str, Any]:
        """
        Execute Python code in Authentik container.

        Args:
            script: Python script to execute

        Returns:
            Parsed JSON output from script
        """
        from adsyslib.core import run

        # Pipe script to docker exec
        result = run(
            f"docker exec -i {self.container_name} python3",
            input=script,
            check=True,
            capture_output=True,
            text=True
        )

        # Parse JSON from last line
        lines = result.stdout.strip().split('\n')
        for line in reversed(lines):
            if line.startswith('{') or line.startswith('['):
                return json.loads(line)

        raise ValueError("No JSON output found in script result")

    def _generate_create_script(self, config: OAuthProviderConfig) -> str:
        """Generate Python script to create OAuth provider."""
        return f'''
import os, sys, json
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'authentik.root.settings')
import django
django.setup()
from authentik.core.models import Application
from authentik.providers.oauth2.models import OAuth2Provider
from authentik.flows.models import Flow, FlowDesignation
from authentik.crypto.models import CertificateKeyPair

flow = Flow.objects.filter(designation=FlowDesignation.AUTHORIZATION).first()
cert = CertificateKeyPair.objects.filter(name="authentik Self-signed Certificate").first()

# Check if provider exists
try:
    provider = OAuth2Provider.objects.get(client_id="{config.client_id}")
    print(json.dumps({{"error": "Provider already exists", "client_id": "{config.client_id}"}}), file=sys.stderr)
    sys.exit(1)
except OAuth2Provider.DoesNotExist:
    pass

# Create provider
redirect_uris_data = {json.dumps([{{"matching_mode": "strict", "url": uri}} for uri in config.redirect_uris])}

provider = OAuth2Provider.objects.create(
    name="{config.app_name} Provider",
    authorization_flow=flow,
    client_id="{config.client_id}",
    client_type="{config.client_type}",
    signing_key=cert,
    sub_mode="hashed_user_id",
    include_claims_in_id_token=True,
    issuer_mode="per_provider",
)

provider._redirect_uris = redirect_uris_data
provider.save()

# Create or update application
try:
    app = Application.objects.get(slug="{config.app_slug}")
    if app.provider != provider:
        app.provider = provider
        app.save()
except Application.DoesNotExist:
    app = Application.objects.create(
        name="{config.app_name}",
        slug="{config.app_slug}",
        provider=provider,
        meta_launch_url="{config.launch_url}"
    )

# Output result
result = {{
    "app_name": "{config.app_name}",
    "app_slug": "{config.app_slug}",
    "client_id": "{config.client_id}",
    "client_secret": provider.client_secret,
    "client_type": "{config.client_type}",
    "redirect_uris": {json.dumps(config.redirect_uris)},
    "launch_url": "{config.launch_url}"
}}

print(json.dumps(result))
'''

    def create_provider(self, config: OAuthProviderConfig) -> Dict[str, Any]:
        """
        Create an OAuth2 provider.

        Args:
            config: Provider configuration

        Returns:
            Dict with provider details including client_secret

        Raises:
            ValueError: If provider already exists
        """
        logger.info(f"Creating OAuth provider: {config.app_name} ({config.client_id})")

        script = self._generate_create_script(config)
        result = self._docker_exec_python(script)

        logger.info(f"✓ Created provider {config.client_id}")
        return result

    def create_providers_bulk(self, configs: List[OAuthProviderConfig]) -> List[Dict[str, Any]]:
        """
        Create multiple OAuth providers in one operation.

        Args:
            configs: List of provider configurations

        Returns:
            List of results (one per provider)
        """
        logger.info(f"Creating {len(configs)} OAuth providers...")

        results = []
        for config in configs:
            try:
                result = self.create_provider(config)
                results.append(result)
            except Exception as e:
                logger.error(f"Failed to create {config.client_id}: {e}")
                results.append({
                    "error": str(e),
                    "client_id": config.client_id,
                    "app_name": config.app_name
                })

        logger.info(f"✓ Created {len([r for r in results if 'error' not in r])}/{len(configs)} providers")
        return results

    def list_providers(self) -> List[Dict[str, Any]]:
        """List all OAuth2 providers."""
        script = '''
import os, sys, json
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'authentik.root.settings')
import django
django.setup()
from authentik.providers.oauth2.models import OAuth2Provider

providers = []
for p in OAuth2Provider.objects.all():
    providers.append({
        "name": p.name,
        "client_id": p.client_id,
        "client_type": p.client_type,
        "redirect_uris": [uri["url"] for uri in p._redirect_uris] if p._redirect_uris else []
    })

print(json.dumps(providers))
'''
        return self._docker_exec_python(script)

    def get_provider(self, client_id: str) -> Dict[str, Any]:
        """
        Get details of a specific provider.

        Args:
            client_id: OAuth client ID

        Returns:
            Provider details including client_secret
        """
        script = f'''
import os, sys, json
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'authentik.root.settings')
import django
django.setup()
from authentik.providers.oauth2.models import OAuth2Provider

try:
    p = OAuth2Provider.objects.get(client_id="{client_id}")
    result = {{
        "name": p.name,
        "client_id": p.client_id,
        "client_secret": p.client_secret,
        "client_type": p.client_type,
        "redirect_uris": [uri["url"] for uri in p._redirect_uris] if p._redirect_uris else []
    }}
    print(json.dumps(result))
except OAuth2Provider.DoesNotExist:
    print(json.dumps({{"error": "Provider not found"}}), file=sys.stderr)
    sys.exit(1)
'''
        return self._docker_exec_python(script)

    def delete_provider(self, client_id: str):
        """
        Delete an OAuth2 provider.

        Args:
            client_id: OAuth client ID to delete
        """
        logger.info(f"Deleting OAuth provider: {client_id}")

        script = f'''
import os, sys, json
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'authentik.root.settings')
import django
django.setup()
from authentik.providers.oauth2.models import OAuth2Provider

try:
    p = OAuth2Provider.objects.get(client_id="{client_id}")
    p.delete()
    print(json.dumps({{"success": True, "client_id": "{client_id}"}}))
except OAuth2Provider.DoesNotExist:
    print(json.dumps({{"error": "Provider not found"}}), file=sys.stderr)
    sys.exit(1)
'''
        self._docker_exec_python(script)
        logger.info(f"✓ Deleted provider {client_id}")


def load_providers_from_json(json_file: str) -> List[OAuthProviderConfig]:
    """
    Load provider configurations from JSON file.

    Args:
        json_file: Path to JSON file with provider configs

    Returns:
        List of OAuthProviderConfig objects
    """
    with open(json_file, 'r') as f:
        data = json.load(f)

    # Handle both formats: {"apps": [...]} or [...]
    apps = data.get("apps", data) if isinstance(data, dict) else data

    configs = []
    for app in apps:
        config = OAuthProviderConfig(
            app_name=app["app_name"],
            app_slug=app["app_slug"],
            client_id=app["client_id"],
            redirect_uris=app["redirect_uris"],
            launch_url=app["launch_url"],
            client_type=app.get("client_type", "confidential"),
            description=app.get("description"),
            port=app.get("port")
        )
        configs.append(config)

    return configs


def generate_env_file(results: List[Dict[str, Any]], output_file: str = ".env"):
    """
    Generate .env file with OAuth credentials.

    Args:
        results: List of provider creation results
        output_file: Output file path
    """
    with open(output_file, 'a') as f:
        f.write('\n\n# ====== OAUTH PROVIDERS ======\n')
        for result in results:
            if 'error' in result:
                continue

            slug = result['app_slug'].upper().replace('-', '_')
            f.write(f'\n# {result["app_name"]}\n')
            f.write(f'{slug}_CLIENT_ID={result["client_id"]}\n')
            f.write(f'{slug}_CLIENT_SECRET={result["client_secret"]}\n')

    logger.info(f"✓ Generated {output_file} with {len(results)} OAuth credentials")
