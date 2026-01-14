"""
LDAP Group Mapper for Identity Federation

Maps LDAP/Active Directory groups to local capabilities.
Supports:
- Active Directory
- OpenLDAP
- FreeIPA
- Generic LDAP v3

IMPORTANT: LDAP identity is ADVISORY only. Ceremonies are still
required for all sensitive operations regardless of group membership.
"""

import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Set, Any, Tuple

logger = logging.getLogger(__name__)

# Try to import LDAP library
try:
    from ldap3 import Server, Connection, ALL, SUBTREE
    LDAP_AVAILABLE = True
except ImportError:
    LDAP_AVAILABLE = False
    logger.warning("ldap3 not available - LDAP integration disabled")


class LDAPServerType(Enum):
    """LDAP server types with provider-specific settings."""
    ACTIVE_DIRECTORY = "active_directory"
    OPENLDAP = "openldap"
    FREEIPA = "freeipa"
    GENERIC = "generic"


@dataclass
class LDAPConfig:
    """Configuration for LDAP connection and mapping."""
    # Server settings
    server_type: LDAPServerType = LDAPServerType.GENERIC
    server_url: str = "ldap://localhost:389"
    use_ssl: bool = False
    use_tls: bool = True
    timeout: int = 10

    # Bind credentials
    bind_dn: str = ""
    bind_password: str = ""

    # Search settings
    base_dn: str = ""
    user_search_base: Optional[str] = None
    group_search_base: Optional[str] = None

    # Attribute mappings
    user_id_attribute: str = "uid"
    user_email_attribute: str = "mail"
    user_name_attribute: str = "cn"
    group_attribute: str = "memberOf"
    group_name_attribute: str = "cn"

    # Active Directory specific
    ad_domain: Optional[str] = None

    # Caching
    cache_groups_seconds: int = 300
    cache_user_seconds: int = 60


@dataclass
class LDAPGroup:
    """Represents an LDAP group."""
    dn: str
    name: str
    description: Optional[str] = None
    members: List[str] = field(default_factory=list)
    nested_groups: List[str] = field(default_factory=list)


@dataclass
class GroupMapping:
    """Maps LDAP groups to capabilities."""
    ldap_group_dn: str
    ldap_group_name: str
    capabilities: Set[str]
    ceremony_bypass: bool = False  # NEVER set to True for sensitive ops


@dataclass
class CapabilitySet:
    """Set of capabilities for a user."""
    user_dn: str
    username: str
    email: Optional[str] = None
    groups: List[str] = field(default_factory=list)
    capabilities: Set[str] = field(default_factory=set)
    ceremony_required: bool = True  # Always True for sensitive ops
    cached_at: Optional[datetime] = None


class LDAPMapper:
    """
    Maps LDAP groups to local capabilities.

    Usage:
        mapper = LDAPMapper(LDAPConfig(
            server_url="ldap://ldap.example.com",
            bind_dn="cn=service,dc=example,dc=com",
            bind_password="secret",
            base_dn="dc=example,dc=com",
        ))

        # Define group mappings
        mapper.add_group_mapping("cn=admins,ou=groups,dc=example,dc=com", {"admin", "read", "write"})
        mapper.add_group_mapping("cn=operators,ou=groups,dc=example,dc=com", {"read", "write"})

        # Get user capabilities
        caps = mapper.get_user_capabilities("username")
        print(f"Capabilities: {caps.capabilities}")
        # Note: caps.ceremony_required is always True for sensitive operations
    """

    def __init__(self, config: LDAPConfig):
        self.config = config
        self._connection: Optional['Connection'] = None
        self._lock = threading.Lock()

        # Group mappings: group_dn -> GroupMapping
        self._group_mappings: Dict[str, GroupMapping] = {}

        # Caches
        self._user_cache: Dict[str, Tuple[CapabilitySet, float]] = {}
        self._group_cache: Dict[str, Tuple[LDAPGroup, float]] = {}

        # Apply server-type specific defaults
        self._apply_server_defaults()

    def _apply_server_defaults(self) -> None:
        """Apply server-type specific attribute defaults."""
        if self.config.server_type == LDAPServerType.ACTIVE_DIRECTORY:
            if not self.config.user_id_attribute:
                self.config.user_id_attribute = "sAMAccountName"
            if not self.config.group_attribute:
                self.config.group_attribute = "memberOf"
            if not self.config.user_name_attribute:
                self.config.user_name_attribute = "displayName"
        elif self.config.server_type == LDAPServerType.FREEIPA:
            if not self.config.user_id_attribute:
                self.config.user_id_attribute = "uid"
            if not self.config.group_attribute:
                self.config.group_attribute = "memberOf"

    def _get_connection(self) -> Optional['Connection']:
        """Get or create LDAP connection."""
        if not LDAP_AVAILABLE:
            logger.error("ldap3 not available")
            return None

        with self._lock:
            if self._connection and self._connection.bound:
                return self._connection

            try:
                server = Server(
                    self.config.server_url,
                    get_info=ALL,
                    connect_timeout=self.config.timeout,
                )

                self._connection = Connection(
                    server,
                    user=self.config.bind_dn,
                    password=self.config.bind_password,
                    auto_bind=True,
                    raise_exceptions=True,
                )

                if self.config.use_tls and not self.config.use_ssl:
                    self._connection.start_tls()

                logger.info(f"Connected to LDAP server: {self.config.server_url}")
                return self._connection

            except Exception as e:
                logger.error(f"LDAP connection failed: {e}")
                return None

    def add_group_mapping(
        self,
        group_dn: str,
        capabilities: Set[str],
        group_name: Optional[str] = None,
    ) -> None:
        """
        Add a mapping from LDAP group to capabilities.

        Args:
            group_dn: Full DN of the LDAP group
            capabilities: Set of capability strings
            group_name: Optional human-readable name
        """
        if group_name is None:
            # Extract CN from DN
            parts = group_dn.split(',')
            for part in parts:
                if part.lower().startswith('cn='):
                    group_name = part[3:]
                    break
            else:
                group_name = group_dn

        self._group_mappings[group_dn.lower()] = GroupMapping(
            ldap_group_dn=group_dn,
            ldap_group_name=group_name,
            capabilities=capabilities,
            ceremony_bypass=False,  # NEVER bypass ceremony
        )

    def remove_group_mapping(self, group_dn: str) -> bool:
        """Remove a group mapping."""
        return self._group_mappings.pop(group_dn.lower(), None) is not None

    def _search_user(self, username: str) -> Optional[Dict[str, Any]]:
        """Search for user by username."""
        conn = self._get_connection()
        if not conn:
            return None

        search_base = self.config.user_search_base or self.config.base_dn
        search_filter = f"({self.config.user_id_attribute}={username})"

        try:
            conn.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=[
                    self.config.user_id_attribute,
                    self.config.user_email_attribute,
                    self.config.user_name_attribute,
                    self.config.group_attribute,
                ],
            )

            if conn.entries:
                entry = conn.entries[0]
                return {
                    'dn': str(entry.entry_dn),
                    'username': str(getattr(entry, self.config.user_id_attribute, '')),
                    'email': str(getattr(entry, self.config.user_email_attribute, '')),
                    'name': str(getattr(entry, self.config.user_name_attribute, '')),
                    'groups': list(getattr(entry, self.config.group_attribute, [])),
                }
            return None

        except Exception as e:
            logger.error(f"LDAP user search failed: {e}")
            return None

    def _get_nested_groups(self, group_dn: str, visited: Optional[Set[str]] = None) -> Set[str]:
        """Get all nested groups (for AD)."""
        if visited is None:
            visited = set()

        if group_dn.lower() in visited:
            return set()

        visited.add(group_dn.lower())
        nested = {group_dn}

        # Only do nested group resolution for AD
        if self.config.server_type != LDAPServerType.ACTIVE_DIRECTORY:
            return nested

        conn = self._get_connection()
        if not conn:
            return nested

        try:
            # Search for groups that have this group as member
            search_filter = f"(member={group_dn})"
            conn.search(
                search_base=self.config.group_search_base or self.config.base_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=['distinguishedName'],
            )

            for entry in conn.entries:
                parent_dn = str(entry.entry_dn)
                nested.update(self._get_nested_groups(parent_dn, visited))

        except Exception as e:
            logger.debug(f"Nested group search failed: {e}")

        return nested

    def get_user_capabilities(
        self,
        username: str,
        use_cache: bool = True,
    ) -> Optional[CapabilitySet]:
        """
        Get capabilities for a user based on their LDAP groups.

        Args:
            username: Username to lookup
            use_cache: Whether to use cached results

        Returns:
            CapabilitySet with user's capabilities
        """
        cache_key = username.lower()

        # Check cache
        if use_cache and cache_key in self._user_cache:
            cached, cache_time = self._user_cache[cache_key]
            if time.time() - cache_time < self.config.cache_user_seconds:
                return cached

        # Search for user
        user_info = self._search_user(username)
        if not user_info:
            logger.warning(f"User not found: {username}")
            return None

        # Get all groups including nested
        all_groups: Set[str] = set()
        for group_dn in user_info.get('groups', []):
            all_groups.update(self._get_nested_groups(str(group_dn)))

        # Map to capabilities
        capabilities: Set[str] = set()
        group_names: List[str] = []

        for group_dn in all_groups:
            mapping = self._group_mappings.get(group_dn.lower())
            if mapping:
                capabilities.update(mapping.capabilities)
                group_names.append(mapping.ldap_group_name)

        result = CapabilitySet(
            user_dn=user_info['dn'],
            username=user_info['username'],
            email=user_info.get('email'),
            groups=group_names,
            capabilities=capabilities,
            ceremony_required=True,  # ALWAYS require ceremony
            cached_at=datetime.utcnow(),
        )

        # Cache result
        self._user_cache[cache_key] = (result, time.time())

        return result

    def validate_user_groups(
        self,
        username: str,
        required_groups: List[str],
    ) -> Tuple[bool, List[str]]:
        """
        Check if user is member of required groups.

        Args:
            username: Username to check
            required_groups: List of required group DNs or names

        Returns:
            (is_member, missing_groups)
        """
        caps = self.get_user_capabilities(username)
        if not caps:
            return (False, required_groups)

        user_groups_lower = {g.lower() for g in caps.groups}
        missing = []

        for required in required_groups:
            # Check by name or DN
            required_lower = required.lower()
            if required_lower not in user_groups_lower:
                # Also check mappings
                found = False
                for mapping in self._group_mappings.values():
                    if (mapping.ldap_group_name.lower() == required_lower or
                            mapping.ldap_group_dn.lower() == required_lower):
                        if mapping.ldap_group_name.lower() in user_groups_lower:
                            found = True
                            break
                if not found:
                    missing.append(required)

        return (len(missing) == 0, missing)

    def clear_cache(self) -> None:
        """Clear all caches."""
        self._user_cache.clear()
        self._group_cache.clear()

    def close(self) -> None:
        """Close LDAP connection."""
        with self._lock:
            if self._connection:
                try:
                    self._connection.unbind()
                except Exception:
                    pass
                self._connection = None


if __name__ == '__main__':
    print("Testing LDAP Mapper...")

    # Create test config (won't actually connect without real server)
    config = LDAPConfig(
        server_type=LDAPServerType.OPENLDAP,
        server_url="ldap://localhost:389",
        bind_dn="cn=admin,dc=example,dc=com",
        bind_password="secret",
        base_dn="dc=example,dc=com",
    )

    mapper = LDAPMapper(config)

    # Add group mappings
    mapper.add_group_mapping(
        "cn=admins,ou=groups,dc=example,dc=com",
        {"admin", "read", "write", "delete"},
    )
    mapper.add_group_mapping(
        "cn=operators,ou=groups,dc=example,dc=com",
        {"read", "write"},
    )
    mapper.add_group_mapping(
        "cn=viewers,ou=groups,dc=example,dc=com",
        {"read"},
    )

    print("\nConfigured group mappings:")
    for dn, mapping in mapper._group_mappings.items():
        print(f"  {mapping.ldap_group_name}: {mapping.capabilities}")

    print("\nNote: Actual LDAP queries require a running LDAP server.")
    print("IMPORTANT: ceremony_required is ALWAYS True for sensitive operations.")

    mapper.close()
    print("\nLDAP mapper test complete.")
