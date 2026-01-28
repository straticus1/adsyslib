"""
Keycloak to Authentik migration utilities.
Helps migrate users, groups, and applications from Keycloak to Authentik.
"""
import logging
from typing import List, Dict, Any, Optional
from adsyslib.keycloak.client import KeycloakClient
from adsyslib.authentik.client import AuthentikClient

logger = logging.getLogger(__name__)


class KeycloakToAuthentikMigrator:
    """
    Migrate data from Keycloak to Authentik.

    IMPORTANT NOTES:
    - Passwords cannot be migrated directly (they're hashed differently)
    - Users will need to reset passwords or use an initial password
    - OAuth client secrets need to be regenerated
    - SAML certificates need to be re-imported
    """

    def __init__(
        self,
        keycloak_client: KeycloakClient,
        authentik_client: AuthentikClient,
        default_password: str = None,
        dry_run: bool = False,
    ):
        """
        Initialize migrator.

        Args:
            keycloak_client: Configured KeycloakClient
            authentik_client: Configured AuthentikClient
            default_password: Default password for migrated users (if None, users must reset)
            dry_run: If True, only log what would be done without making changes
        """
        self.keycloak = keycloak_client
        self.authentik = authentik_client
        self.default_password = default_password
        self.dry_run = dry_run
        self.migration_report = {
            "users_migrated": 0,
            "users_failed": 0,
            "groups_migrated": 0,
            "groups_failed": 0,
            "errors": [],
        }

    def migrate_groups(self) -> Dict[str, str]:
        """
        Migrate groups from Keycloak to Authentik.

        Returns:
            Mapping of Keycloak group names to Authentik group UUIDs
        """
        logger.info("Migrating groups from Keycloak to Authentik")
        keycloak_groups = self.keycloak.list_groups()
        group_mapping = {}

        for kc_group in keycloak_groups:
            group_name = kc_group["name"]

            try:
                if self.dry_run:
                    logger.info(f"[DRY RUN] Would create group: {group_name}")
                    group_mapping[group_name] = f"dry-run-uuid-{group_name}"
                else:
                    # Check if group already exists
                    existing = self.authentik.list_groups(search=group_name)
                    if existing and any(g["name"] == group_name for g in existing):
                        logger.info(f"Group already exists: {group_name}")
                        group_id = next(
                            g["pk"] for g in existing if g["name"] == group_name
                        )
                        group_mapping[group_name] = group_id
                    else:
                        # Create new group
                        result = self.authentik.create_group(
                            name=group_name,
                            attributes=kc_group.get("attributes", {}),
                        )
                        group_id = result["pk"]
                        group_mapping[group_name] = group_id
                        logger.info(f"Created group: {group_name} -> {group_id}")

                self.migration_report["groups_migrated"] += 1

            except Exception as e:
                logger.error(f"Failed to migrate group {group_name}: {e}")
                self.migration_report["groups_failed"] += 1
                self.migration_report["errors"].append(
                    {"type": "group", "name": group_name, "error": str(e)}
                )

        logger.info(
            f"Group migration complete: {self.migration_report['groups_migrated']} succeeded, "
            f"{self.migration_report['groups_failed']} failed"
        )

        return group_mapping

    def migrate_users(
        self, group_mapping: Dict[str, str] = None, send_password_reset: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Migrate users from Keycloak to Authentik.

        Args:
            group_mapping: Optional mapping of Keycloak group names to Authentik UUIDs
            send_password_reset: Whether to send password reset emails (requires email config)

        Returns:
            List of migration results for each user
        """
        logger.info("Migrating users from Keycloak to Authentik")
        keycloak_users = self.keycloak.export_users_minimal()
        results = []

        for kc_user in keycloak_users:
            username = kc_user["username"]

            try:
                # Build Authentik user data
                name = f"{kc_user.get('firstName', '')} {kc_user.get('lastName', '')}".strip() or username
                email = kc_user.get("email")

                # Map groups
                authentik_groups = []
                if group_mapping and kc_user.get("groups"):
                    for group_name in kc_user["groups"]:
                        if group_name in group_mapping:
                            authentik_groups.append(group_mapping[group_name])

                if self.dry_run:
                    logger.info(
                        f"[DRY RUN] Would create user: {username} ({name}) with groups {authentik_groups}"
                    )
                    results.append(
                        {
                            "username": username,
                            "status": "dry_run",
                            "authentik_id": None,
                        }
                    )
                else:
                    # Check if user exists
                    existing = self.authentik.list_users(search=username)
                    if existing and any(u["username"] == username for u in existing):
                        logger.info(f"User already exists: {username}")
                        user_id = next(
                            u["pk"] for u in existing if u["username"] == username
                        )
                        results.append(
                            {
                                "username": username,
                                "status": "exists",
                                "authentik_id": user_id,
                            }
                        )
                    else:
                        # Create user
                        user = self.authentik.create_user(
                            username=username,
                            name=name,
                            email=email,
                            is_active=kc_user.get("enabled", True),
                            groups=authentik_groups,
                            attributes=kc_user.get("attributes", {}),
                        )
                        user_id = user["pk"]
                        logger.info(f"Created user: {username} -> {user_id}")

                        # Set password if provided
                        if self.default_password:
                            try:
                                self.authentik.set_user_password(
                                    user_id, self.default_password
                                )
                                logger.debug(f"Set default password for {username}")
                            except Exception as e:
                                logger.warning(
                                    f"Failed to set password for {username}: {e}"
                                )

                        results.append(
                            {
                                "username": username,
                                "status": "created",
                                "authentik_id": user_id,
                            }
                        )

                self.migration_report["users_migrated"] += 1

            except Exception as e:
                logger.error(f"Failed to migrate user {username}: {e}")
                self.migration_report["users_failed"] += 1
                self.migration_report["errors"].append(
                    {"type": "user", "username": username, "error": str(e)}
                )
                results.append({"username": username, "status": "failed", "error": str(e)})

        logger.info(
            f"User migration complete: {self.migration_report['users_migrated']} succeeded, "
            f"{self.migration_report['users_failed']} failed"
        )

        return results

    def migrate_all(self) -> Dict[str, Any]:
        """
        Perform full migration: groups, then users.

        Returns:
            Complete migration report
        """
        logger.info("Starting full Keycloak to Authentik migration")

        # Step 1: Migrate groups
        group_mapping = self.migrate_groups()

        # Step 2: Migrate users with group associations
        user_results = self.migrate_users(group_mapping=group_mapping)

        # Build final report
        report = {
            **self.migration_report,
            "group_mapping": group_mapping,
            "user_results": user_results,
        }

        logger.info("=" * 60)
        logger.info("MIGRATION SUMMARY")
        logger.info("=" * 60)
        logger.info(f"Groups migrated: {report['groups_migrated']}")
        logger.info(f"Groups failed: {report['groups_failed']}")
        logger.info(f"Users migrated: {report['users_migrated']}")
        logger.info(f"Users failed: {report['users_failed']}")
        logger.info(f"Total errors: {len(report['errors'])}")

        if report["errors"]:
            logger.warning("\nErrors encountered:")
            for error in report["errors"][:10]:  # Show first 10
                logger.warning(f"  - {error['type']}: {error.get('name', error.get('username'))} - {error['error']}")

        logger.info("=" * 60)

        return report

    def generate_migration_report(self, output_file: str = "migration_report.json"):
        """Save migration report to a file."""
        import json

        with open(output_file, "w") as f:
            json.dump(self.migration_report, f, indent=2)

        logger.info(f"Migration report saved to {output_file}")


def quick_migrate(
    keycloak_url: str,
    keycloak_realm: str,
    keycloak_username: str,
    keycloak_password: str,
    authentik_url: str,
    authentik_token: str,
    default_password: str = None,
    dry_run: bool = True,
) -> Dict[str, Any]:
    """
    Quick migration helper function.

    Args:
        keycloak_url: Keycloak base URL
        keycloak_realm: Keycloak realm to migrate
        keycloak_username: Keycloak admin username
        keycloak_password: Keycloak admin password
        authentik_url: Authentik base URL
        authentik_token: Authentik API token
        default_password: Default password for migrated users
        dry_run: If True, don't make actual changes

    Returns:
        Migration report
    """
    logger.info("Initializing quick migration")

    # Initialize clients
    kc = KeycloakClient(
        base_url=keycloak_url,
        realm=keycloak_realm,
        username=keycloak_username,
        password=keycloak_password,
    )

    ak = AuthentikClient(base_url=authentik_url, api_token=authentik_token)

    # Create migrator and run
    migrator = KeycloakToAuthentikMigrator(
        keycloak_client=kc,
        authentik_client=ak,
        default_password=default_password,
        dry_run=dry_run,
    )

    return migrator.migrate_all()
