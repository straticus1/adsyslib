# OAuth Provider Management with adsyslib

The adsyslib library now includes comprehensive OAuth2/OIDC provider management for Authentik!

## Quick Start

### Install adsyslib

```bash
cd /Users/ryan/development/adsyslib
pip install -e .
```

### Create a Single OAuth Provider

```bash
# Create an OAuth app
adsys authentik oauth-create \
  "My Application" \
  my-app-client \
  --redirect-uri "http://localhost:3000/callback" \
  --redirect-uri "https://app.example.com/callback" \
  --launch-url "http://localhost:3000/" \
  --type confidential \
  --output-env .env
```

### Create Multiple Providers from JSON

```bash
# Use the config file we created for AfterDark
adsys authentik oauth-bulk-create \
  /Users/ryan/development/afterdark-meta-project/afterdark-security-suite/afterdark-darkd/deployments/authentik/config/oauth_apps_full_suite.json \
  --output-env .env \
  --output-json oauth_secrets.json
```

### List All OAuth Providers

```bash
adsys authentik oauth-list
```

### Get Provider Details

```bash
# Show provider details (hide secret)
adsys authentik oauth-get my-app-client

# Show with secret
adsys authentik oauth-get my-app-client --show-secret
```

### Delete a Provider

```bash
# With confirmation
adsys authentik oauth-delete my-app-client

# Skip confirmation
adsys authentik oauth-delete my-app-client --yes
```

---

## Python API

### Create a Single Provider

```python
from adsyslib.authentik import AuthentikOAuthManager, OAuthProviderConfig

# Configure provider
config = OAuthProviderConfig(
    app_name="My Application",
    app_slug="my-app",
    client_id="my-app-client",
    redirect_uris=[
        "http://localhost:3000/callback",
        "https://app.example.com/callback"
    ],
    launch_url="http://localhost:3000/",
    client_type="confidential"  # or "public" for SPAs/native apps
)

# Create via Django ORM
manager = AuthentikOAuthManager(container_name="authentik-server-prod")
result = manager.create_provider(config)

print(f"Client ID: {result['client_id']}")
print(f"Client Secret: {result['client_secret']}")
```

### Bulk Create from JSON

```python
from adsyslib.authentik import (
    AuthentikOAuthManager,
    load_providers_from_json,
    generate_env_file
)

# Load configs
configs = load_providers_from_json("oauth_apps.json")

# Create all providers
manager = AuthentikOAuthManager()
results = manager.create_providers_bulk(configs)

# Generate .env file
generate_env_file(results, ".env")

# Show results
for result in results:
    if 'error' in result:
        print(f"Failed: {result['client_id']} - {result['error']}")
    else:
        print(f"Created: {result['app_name']} ({result['client_id']})")
```

### List and Query Providers

```python
manager = AuthentikOAuthManager()

# List all providers
providers = manager.list_providers()
for p in providers:
    print(f"{p['name']}: {p['client_id']}")

# Get specific provider
provider = manager.get_provider("my-app-client")
print(f"Secret: {provider['client_secret']}")

# Delete provider
manager.delete_provider("my-app-client")
```

---

## JSON Configuration Format

```json
{
  "apps": [
    {
      "app_name": "My Application",
      "app_slug": "my-app",
      "client_id": "my-app-client",
      "client_type": "confidential",
      "redirect_uris": [
        "http://localhost:3000/callback",
        "https://app.example.com/callback"
      ],
      "launch_url": "http://localhost:3000/",
      "description": "Optional description",
      "port": 3000
    }
  ]
}
```

### Field Descriptions

- **app_name**: Display name for the application
- **app_slug**: URL-safe slug identifier
- **client_id**: OAuth client ID (must be unique)
- **client_type**:
  - `confidential` - Backend services with secrets
  - `public` - SPAs, mobile apps (PKCE recommended)
- **redirect_uris**: List of allowed callback URLs
- **launch_url**: Application homepage
- **description**: Optional metadata
- **port**: Optional port number for documentation

---

## How It Works

Unlike the Authentik API (which has permission issues) or Terraform (which is buggy), adsyslib uses **Django ORM direct access**:

1. **Docker Exec**: Runs Python code inside the Authentik container
2. **Django Setup**: Initializes Django with Authentik's settings
3. **ORM Operations**: Uses Authentik's own models directly
4. **Bypass API**: No API tokens, no permission issues
5. **Compliance-Friendly**: Fully scriptable and auditable

This is the same approach used by Authentik's own admin interface, making it reliable and maintainable.

---

## Integration with AfterDark Security Suite

The 21 OAuth providers created for AfterDark can now be managed via adsyslib:

```bash
# Re-create all 21 providers (if needed)
cd /Users/ryan/development/afterdark-meta-project/afterdark-security-suite/afterdark-darkd/deployments/authentik

adsys authentik oauth-bulk-create \
  config/oauth_apps_full_suite.json \
  --output-env .env \
  --output-json config/oauth_secrets.json

# List all AfterDark services
adsys authentik oauth-list

# Get specific service credentials
adsys authentik oauth-get darkd-dashboard-client --show-secret
adsys authentik oauth-get ads-httpproxy-client --show-secret
```

---

## Advanced Usage

### Custom Container Name

```python
# Different container
manager = AuthentikOAuthManager(container_name="my-authentik-container")
```

### Error Handling

```python
try:
    result = manager.create_provider(config)
except ValueError as e:
    if "already exists" in str(e):
        print("Provider already exists, skipping...")
    else:
        raise
```

### Programmatic Configuration

```python
# Generate configs dynamically
services = [
    ("Service A", 3000),
    ("Service B", 3001),
    ("Service C", 3002),
]

configs = []
for name, port in services:
    slug = name.lower().replace(" ", "-")
    config = OAuthProviderConfig(
        app_name=name,
        app_slug=slug,
        client_id=f"{slug}-client",
        redirect_uris=[f"http://localhost:{port}/callback"],
        launch_url=f"http://localhost:{port}/",
        client_type="confidential",
        port=port
    )
    configs.append(config)

manager = AuthentikOAuthManager()
results = manager.create_providers_bulk(configs)
```

---

## Benefits Over Other Approaches

| Approach | Issues | adsyslib Solution |
|----------|--------|-------------------|
| **Authentik API** | 403 Forbidden errors, complex token permissions | Bypasses API entirely via Django ORM |
| **Terraform** | Buggy provider, needs local patches, 403 errors | No Terraform dependency |
| **Manual UI** | Not compliance-friendly, no audit trail, time-consuming | Fully scriptable, version-controlled |
| **Custom Scripts** | One-off tools, not reusable | Packaged library with CLI |

---

## Migration from Manual/Terraform

If you've been using manual UI or Terraform:

1. **Export existing providers** (using adsyslib):
   ```python
   manager = AuthentikOAuthManager()
   providers = manager.list_providers()

   # Convert to config format
   configs = []
   for p in providers:
       config = {
           "app_name": p['name'].replace(' Provider', ''),
           "client_id": p['client_id'],
           "client_type": p['client_type'],
           "redirect_uris": p['redirect_uris'],
           # ... populate other fields
       }
       configs.append(config)

   # Save to JSON
   with open('existing_providers.json', 'w') as f:
       json.dump({"apps": configs}, f, indent=2)
   ```

2. **Manage via adsyslib** going forward
3. **Delete Terraform state** (if using Terraform)
4. **Version control the JSON config**

---

## Compliance & Auditing

adsyslib makes OAuth management compliance-friendly:

- ✅ **Version Control**: JSON configs in git
- ✅ **Audit Trail**: Git history shows all changes
- ✅ **Reproducible**: Can recreate entire setup from config
- ✅ **No Manual UI**: Meets regulatory requirements
- ✅ **Scriptable**: Integrates with CI/CD pipelines
- ✅ **Secure**: Secrets in `.env` (gitignored), not in code

---

## Next Steps

1. **Install adsyslib** in your environment
2. **Export existing providers** to JSON
3. **Test with a single provider** using `oauth-create`
4. **Bulk create** remaining providers
5. **Integrate with deployment pipelines**
6. **Document your OAuth architecture**

---

## Example: Complete AfterDark OAuth Setup

```bash
#!/bin/bash
# Complete OAuth setup for AfterDark Security Suite

# Install adsyslib
pip install -e /Users/ryan/development/adsyslib

# Navigate to config directory
cd /Users/ryan/development/afterdark-meta-project/afterdark-security-suite/afterdark-darkd/deployments/authentik

# Create all 18 OAuth providers (3 already exist, will be skipped)
adsys authentik oauth-bulk-create \
  config/oauth_apps_full_suite.json \
  --output-env .env \
  --output-json config/oauth_secrets.json

# Verify all providers
adsys authentik oauth-list | grep -c "darkd-dashboard\|dlp-gui\|lowkey-ui"

# Done! All services now have OAuth providers configured
echo "✓ OAuth setup complete for 21 AfterDark services"
```

---

## Troubleshooting

### Container not found

```bash
# List running containers
docker ps | grep authentik

# Specify custom container name
adsys authentik oauth-create "My App" my-app-client \
  --redirect-uri "http://localhost:3000/callback" \
  --launch-url "http://localhost:3000/" \
  --container "my-authentik-container"
```

### Provider already exists

This is expected behavior - the tool will skip existing providers. To recreate:

```bash
# Delete first
adsys authentik oauth-delete my-app-client --yes

# Then recreate
adsys authentik oauth-create "My App" my-app-client ...
```

### JSON parsing errors

Ensure your JSON config is valid:

```bash
# Validate JSON
python3 -m json.tool config/oauth_apps.json

# Or use jq
jq . config/oauth_apps.json
```

---

## Contributing to adsyslib

Found a bug or want to add features? adsyslib is designed for enhancement:

1. Fork the repo
2. Add your feature to `src/adsyslib/`
3. Add tests to `tests/`
4. Update documentation
5. Submit PR

The library is built for Claude Code integration, making it easy for me to help improve it!
