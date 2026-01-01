"""
MAC Profile Generator for Sandbox Isolation

Generates AppArmor and SELinux profiles for sandbox processes based on
sandbox configuration and boundary mode requirements.

Features:
- Auto-generate AppArmor profiles from sandbox configuration
- Auto-generate SELinux policy modules from sandbox configuration
- Profile templates for common boundary modes
- Integration with sandbox manager for automatic profile application
- Profile caching and validation

Usage:
    from daemon.sandbox.mac_profiles import MACProfileGenerator, get_mac_generator

    generator = get_mac_generator()

    # Generate AppArmor profile for a sandbox
    profile = generator.generate_apparmor_profile(
        sandbox_id="sbx-001",
        profile=sandbox_profile,
    )

    # Apply the profile
    generator.apply_apparmor_profile(sandbox_id, profile)

    # Or generate SELinux policy
    policy = generator.generate_selinux_policy(
        sandbox_id="sbx-001",
        profile=sandbox_profile,
    )
"""

import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any

logger = logging.getLogger(__name__)


class MACSystem(Enum):
    """Mandatory Access Control systems."""
    APPARMOR = "apparmor"
    SELINUX = "selinux"
    NONE = "none"


class ProfileMode(Enum):
    """Profile enforcement mode."""
    ENFORCE = "enforce"
    COMPLAIN = "complain"  # AppArmor: log but allow
    PERMISSIVE = "permissive"  # SELinux: log but allow
    DISABLED = "disabled"


@dataclass
class FileAccess:
    """File access permission."""
    path: str
    read: bool = False
    write: bool = False
    execute: bool = False
    append: bool = False
    link: bool = False
    lock: bool = False

    def to_apparmor(self) -> str:
        """Convert to AppArmor permission string."""
        perms = []
        if self.read:
            perms.append('r')
        if self.write:
            perms.append('w')
        if self.append:
            perms.append('a')
        if self.execute:
            perms.append('ix')  # inherit execute
        if self.link:
            perms.append('l')
        if self.lock:
            perms.append('k')
        return ''.join(perms) if perms else 'r'


@dataclass
class NetworkAccess:
    """Network access permission."""
    protocol: str = "tcp"  # tcp, udp, raw
    direction: str = "both"  # in, out, both
    ports: List[int] = field(default_factory=list)


@dataclass
class CapabilityAccess:
    """Linux capability permission."""
    capabilities: List[str] = field(default_factory=list)


@dataclass
class MACProfileConfig:
    """Configuration for MAC profile generation."""
    # Basic settings
    sandbox_id: str
    profile_name: str
    mode: ProfileMode = ProfileMode.ENFORCE

    # File access
    file_read: List[str] = field(default_factory=list)
    file_write: List[str] = field(default_factory=list)
    file_execute: List[str] = field(default_factory=list)
    file_deny: List[str] = field(default_factory=list)

    # Network access
    network_enabled: bool = True
    network_protocols: List[str] = field(default_factory=lambda: ["tcp", "udp"])
    network_ports: List[int] = field(default_factory=list)
    network_deny_all: bool = False

    # Capabilities
    capabilities_allow: List[str] = field(default_factory=list)
    capabilities_deny: List[str] = field(default_factory=list)

    # Process restrictions
    allow_ptrace: bool = False
    allow_mount: bool = False
    allow_raw_sockets: bool = False

    # IPC restrictions
    allow_dbus: bool = False
    allow_signals: bool = True

    # Additional includes
    apparmor_includes: List[str] = field(default_factory=list)
    selinux_modules: List[str] = field(default_factory=list)

    @classmethod
    def from_sandbox_profile(cls, sandbox_id: str, sandbox_profile: Any) -> 'MACProfileConfig':
        """Create MAC config from sandbox profile."""
        config = cls(
            sandbox_id=sandbox_id,
            profile_name=f"boundary_sandbox_{sandbox_id}",
        )

        # Map boundary mode to restrictions
        profile_name = getattr(sandbox_profile, 'name', 'standard').upper()

        if profile_name in ('COLDROOM', 'LOCKDOWN'):
            # Maximum restrictions
            config.network_deny_all = True
            config.allow_ptrace = False
            config.allow_mount = False
            config.allow_raw_sockets = False
            config.allow_dbus = False
            config.file_deny = ['/proc/sys/**', '/sys/**', '/dev/**']
            config.file_read = ['/usr/**', '/lib/**', '/lib64/**', '/etc/ld.so.cache']
            config.file_execute = ['/usr/bin/**', '/bin/**']

        elif profile_name == 'AIRGAP':
            # Network disabled
            config.network_deny_all = True
            config.allow_ptrace = False
            config.allow_mount = False
            config.file_read = ['/usr/**', '/lib/**', '/lib64/**', '/etc/**', '/tmp/**']
            config.file_write = ['/tmp/**', '/var/tmp/**']
            config.file_execute = ['/usr/bin/**', '/bin/**', '/usr/local/bin/**']

        elif profile_name in ('RESTRICTED', 'TRUSTED'):
            # Limited network and filesystem
            config.network_enabled = True
            config.allow_ptrace = False
            config.file_read = ['/usr/**', '/lib/**', '/lib64/**', '/etc/**', '/tmp/**', '/home/**']
            config.file_write = ['/tmp/**', '/var/tmp/**']
            config.file_execute = ['/usr/bin/**', '/bin/**', '/usr/local/bin/**']

        else:  # OPEN, STANDARD
            # Permissive but still sandboxed
            config.network_enabled = True
            config.allow_ptrace = False
            config.file_read = ['/**']
            config.file_write = ['/tmp/**', '/var/tmp/**', '/home/**']
            config.file_execute = ['/usr/bin/**', '/bin/**', '/usr/local/bin/**', '/home/**']
            config.file_deny = ['/etc/shadow', '/etc/passwd-', '/root/**']

        # Apply network policy if present
        network_policy = getattr(sandbox_profile, 'network_policy', None)
        if network_policy:
            if getattr(network_policy, 'deny_all', False):
                config.network_deny_all = True
            elif hasattr(network_policy, 'allowed_ports'):
                config.network_ports = list(network_policy.allowed_ports)

        return config


class AppArmorProfileGenerator:
    """Generate AppArmor profiles for sandboxes."""

    PROFILE_TEMPLATE = '''# AppArmor profile for Boundary Daemon sandbox
# Generated: {timestamp}
# Sandbox ID: {sandbox_id}

#include <tunables/global>

profile {profile_name} flags=(attach_disconnected,mediate_deleted) {{
    #include <abstractions/base>
{includes}

    # Capabilities
{capabilities}

    # Network access
{network}

    # File access
{file_rules}

    # Deny rules
{deny_rules}

    # Signal handling
{signals}

    # Additional restrictions
{restrictions}
}}
'''

    def __init__(self, profiles_dir: str = "/etc/apparmor.d"):
        self.profiles_dir = Path(profiles_dir)
        self._profile_cache: Dict[str, str] = {}

    def generate_profile(self, config: MACProfileConfig) -> str:
        """Generate an AppArmor profile from configuration."""
        timestamp = datetime.utcnow().isoformat() + 'Z'

        # Build includes
        includes = self._build_includes(config)

        # Build capabilities
        capabilities = self._build_capabilities(config)

        # Build network rules
        network = self._build_network_rules(config)

        # Build file rules
        file_rules = self._build_file_rules(config)

        # Build deny rules
        deny_rules = self._build_deny_rules(config)

        # Build signal rules
        signals = self._build_signal_rules(config)

        # Build restrictions
        restrictions = self._build_restrictions(config)

        profile = self.PROFILE_TEMPLATE.format(
            timestamp=timestamp,
            sandbox_id=config.sandbox_id,
            profile_name=config.profile_name,
            includes=includes,
            capabilities=capabilities,
            network=network,
            file_rules=file_rules,
            deny_rules=deny_rules,
            signals=signals,
            restrictions=restrictions,
        )

        # Cache the profile
        self._profile_cache[config.sandbox_id] = profile

        return profile

    def _build_includes(self, config: MACProfileConfig) -> str:
        """Build AppArmor includes section."""
        includes = []

        # Standard abstractions
        includes.append("    #include <abstractions/nameservice>")

        # Add custom includes
        for inc in config.apparmor_includes:
            includes.append(f"    #include <{inc}>")

        return '\n'.join(includes) if includes else "    # No additional includes"

    def _build_capabilities(self, config: MACProfileConfig) -> str:
        """Build capabilities section."""
        rules = []

        # Allowed capabilities
        for cap in config.capabilities_allow:
            rules.append(f"    capability {cap},")

        # Denied capabilities
        for cap in config.capabilities_deny:
            rules.append(f"    deny capability {cap},")

        # Default denials based on config
        if not config.allow_mount:
            rules.append("    deny capability sys_admin,")
        if not config.allow_ptrace:
            rules.append("    deny capability sys_ptrace,")
        if not config.allow_raw_sockets:
            rules.append("    deny capability net_raw,")

        return '\n'.join(rules) if rules else "    # Default capabilities"

    def _build_network_rules(self, config: MACProfileConfig) -> str:
        """Build network access rules."""
        rules = []

        if config.network_deny_all:
            rules.append("    deny network,")
        elif config.network_enabled:
            for proto in config.network_protocols:
                rules.append(f"    network {proto},")
            # Allow DNS
            rules.append("    network udp,  # DNS")
        else:
            rules.append("    deny network,")

        return '\n'.join(rules) if rules else "    # Network disabled"

    def _build_file_rules(self, config: MACProfileConfig) -> str:
        """Build file access rules."""
        rules = []

        # Read access
        for path in config.file_read:
            rules.append(f"    {path} r,")

        # Write access
        for path in config.file_write:
            rules.append(f"    {path} rw,")

        # Execute access
        for path in config.file_execute:
            rules.append(f"    {path} rix,")

        # Standard paths
        rules.extend([
            "    /proc/*/maps r,",
            "    /proc/*/stat r,",
            "    /proc/*/status r,",
            "    /dev/null rw,",
            "    /dev/zero r,",
            "    /dev/urandom r,",
            "    /dev/random r,",
        ])

        return '\n'.join(rules)

    def _build_deny_rules(self, config: MACProfileConfig) -> str:
        """Build explicit deny rules."""
        rules = []

        for path in config.file_deny:
            rules.append(f"    deny {path} rwxl,")

        # Standard security denials
        rules.extend([
            "    deny /etc/shadow* rwxl,",
            "    deny /etc/gshadow* rwxl,",
            "    deny /etc/sudoers* rwxl,",
            "    deny /root/.ssh/** rwxl,",
        ])

        return '\n'.join(rules)

    def _build_signal_rules(self, config: MACProfileConfig) -> str:
        """Build signal handling rules."""
        if config.allow_signals:
            return "    signal (receive) peer=unconfined,"
        return "    deny signal,"

    def _build_restrictions(self, config: MACProfileConfig) -> str:
        """Build additional restrictions."""
        rules = []

        if not config.allow_ptrace:
            rules.append("    deny ptrace,")

        if not config.allow_mount:
            rules.append("    deny mount,")
            rules.append("    deny umount,")

        if not config.allow_dbus:
            rules.append("    deny dbus,")

        return '\n'.join(rules) if rules else "    # No additional restrictions"

    def write_profile(self, config: MACProfileConfig, profile_content: str) -> Path:
        """Write profile to disk."""
        profile_path = self.profiles_dir / config.profile_name

        try:
            with open(profile_path, 'w') as f:
                f.write(profile_content)
            logger.info(f"Wrote AppArmor profile to {profile_path}")
            return profile_path
        except Exception as e:
            logger.error(f"Failed to write AppArmor profile: {e}")
            raise

    def load_profile(self, profile_name: str) -> Tuple[bool, str]:
        """Load/reload an AppArmor profile."""
        try:
            result = subprocess.run(
                ['apparmor_parser', '-r', '-W', str(self.profiles_dir / profile_name)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                return True, "Profile loaded successfully"
            return False, result.stderr
        except FileNotFoundError:
            return False, "apparmor_parser not found"
        except Exception as e:
            return False, str(e)

    def unload_profile(self, profile_name: str) -> Tuple[bool, str]:
        """Unload an AppArmor profile."""
        try:
            result = subprocess.run(
                ['apparmor_parser', '-R', str(self.profiles_dir / profile_name)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                return True, "Profile unloaded successfully"
            return False, result.stderr
        except Exception as e:
            return False, str(e)

    def get_cached_profile(self, sandbox_id: str) -> Optional[str]:
        """Get cached profile content."""
        return self._profile_cache.get(sandbox_id)


class SELinuxPolicyGenerator:
    """Generate SELinux policy modules for sandboxes."""

    TYPE_ENFORCEMENT_TEMPLATE = '''# SELinux Type Enforcement for Boundary Daemon sandbox
# Generated: {timestamp}
# Sandbox ID: {sandbox_id}

policy_module({module_name}, 1.0.0)

require {{
    type unconfined_t;
    type bin_t;
    type lib_t;
    type tmp_t;
    type var_t;
    type proc_t;
    type devpts_t;
    type null_device_t;
    type zero_device_t;
    type random_device_t;
    type urandom_device_t;
    class file {{ read write execute getattr open }};
    class dir {{ search read getattr open }};
    class process {{ fork sigchld signal transition }};
    class capability {{ {capabilities} }};
    class tcp_socket {{ create connect accept listen bind getattr }};
    class udp_socket {{ create connect bind getattr }};
}}

# Define sandbox type
type {type_name};
type {type_name}_exec_t;

# Domain transitions
domain_type({type_name})
domain_entry_file({type_name}, {type_name}_exec_t)

# File access
{file_access}

# Network access
{network_access}

# Process permissions
{process_access}

# Deny rules
{deny_rules}
'''

    FILE_CONTEXTS_TEMPLATE = '''# SELinux file contexts for Boundary Daemon sandbox
# Generated: {timestamp}

{contexts}
'''

    def __init__(self, modules_dir: str = "/tmp/boundary-selinux"):
        self.modules_dir = Path(modules_dir)
        self.modules_dir.mkdir(parents=True, exist_ok=True)
        self._module_cache: Dict[str, Tuple[str, str]] = {}

    def generate_policy(self, config: MACProfileConfig) -> Tuple[str, str]:
        """Generate SELinux policy module (TE and FC files)."""
        timestamp = datetime.utcnow().isoformat() + 'Z'
        module_name = f"boundary_sandbox_{config.sandbox_id.replace('-', '_')}"
        type_name = f"boundary_sbx_{config.sandbox_id.replace('-', '_')}_t"

        # Build capabilities
        capabilities = self._build_capabilities(config)

        # Build file access
        file_access = self._build_file_access(config, type_name)

        # Build network access
        network_access = self._build_network_access(config, type_name)

        # Build process access
        process_access = self._build_process_access(config, type_name)

        # Build deny rules
        deny_rules = self._build_deny_rules(config, type_name)

        te_content = self.TYPE_ENFORCEMENT_TEMPLATE.format(
            timestamp=timestamp,
            sandbox_id=config.sandbox_id,
            module_name=module_name,
            type_name=type_name,
            capabilities=capabilities,
            file_access=file_access,
            network_access=network_access,
            process_access=process_access,
            deny_rules=deny_rules,
        )

        # Generate file contexts
        fc_content = self._generate_file_contexts(config, type_name, timestamp)

        # Cache the policy
        self._module_cache[config.sandbox_id] = (te_content, fc_content)

        return te_content, fc_content

    def _build_capabilities(self, config: MACProfileConfig) -> str:
        """Build capabilities list."""
        caps = set(config.capabilities_allow)

        # Add defaults based on config
        if config.allow_mount:
            caps.add('sys_admin')
        if config.allow_ptrace:
            caps.add('sys_ptrace')
        if config.allow_raw_sockets:
            caps.add('net_raw')

        # Always allow basic capabilities
        caps.add('chown')
        caps.add('dac_override')
        caps.add('setuid')
        caps.add('setgid')

        return ' '.join(caps) if caps else 'chown'

    def _build_file_access(self, config: MACProfileConfig, type_name: str) -> str:
        """Build file access rules."""
        rules = []

        # Read access
        rules.append(f"allow {type_name} bin_t:file {{ read getattr open execute }};")
        rules.append(f"allow {type_name} lib_t:file {{ read getattr open execute }};")

        # Tmp access
        if any('/tmp' in p for p in config.file_write):
            rules.append(f"allow {type_name} tmp_t:file {{ create read write getattr open unlink }};")
            rules.append(f"allow {type_name} tmp_t:dir {{ create read write getattr open search add_name remove_name }};")

        # Dev access
        rules.append(f"allow {type_name} null_device_t:chr_file {{ read write getattr open }};")
        rules.append(f"allow {type_name} zero_device_t:chr_file {{ read getattr open }};")
        rules.append(f"allow {type_name} random_device_t:chr_file {{ read getattr open }};")
        rules.append(f"allow {type_name} urandom_device_t:chr_file {{ read getattr open }};")

        # Proc access
        rules.append(f"allow {type_name} proc_t:file {{ read getattr open }};")
        rules.append(f"allow {type_name} proc_t:dir {{ read getattr open search }};")

        return '\n'.join(rules)

    def _build_network_access(self, config: MACProfileConfig, type_name: str) -> str:
        """Build network access rules."""
        rules = []

        if config.network_deny_all:
            rules.append(f"# Network denied")
        elif config.network_enabled:
            if 'tcp' in config.network_protocols:
                rules.append(f"allow {type_name} self:tcp_socket {{ create connect accept listen bind getattr }};")
            if 'udp' in config.network_protocols:
                rules.append(f"allow {type_name} self:udp_socket {{ create connect bind getattr }};")
            # DNS always allowed if network enabled
            rules.append(f"# DNS access via UDP")

        return '\n'.join(rules) if rules else "# No network access"

    def _build_process_access(self, config: MACProfileConfig, type_name: str) -> str:
        """Build process access rules."""
        rules = []

        rules.append(f"allow {type_name} self:process {{ fork sigchld signal }};")

        if config.allow_ptrace:
            rules.append(f"allow {type_name} self:process ptrace;")
        else:
            rules.append(f"# ptrace denied")

        return '\n'.join(rules)

    def _build_deny_rules(self, config: MACProfileConfig, type_name: str) -> str:
        """Build denial rules."""
        rules = []

        # Deny shadow file access
        rules.append(f"# Deny sensitive files")
        rules.append(f"neverallow {type_name} shadow_t:file *;")

        if not config.allow_mount:
            rules.append(f"# Deny mount operations")

        return '\n'.join(rules)

    def _generate_file_contexts(self, config: MACProfileConfig, type_name: str, timestamp: str) -> str:
        """Generate file contexts file."""
        contexts = []

        # Executable context
        contexts.append(f"/usr/bin/boundary-sandbox    --    gen_context({type_name}_exec_t,s0)")

        return self.FILE_CONTEXTS_TEMPLATE.format(
            timestamp=timestamp,
            contexts='\n'.join(contexts),
        )

    def write_policy(self, config: MACProfileConfig, te_content: str, fc_content: str) -> Tuple[Path, Path]:
        """Write policy files to disk."""
        module_name = f"boundary_sandbox_{config.sandbox_id.replace('-', '_')}"

        te_path = self.modules_dir / f"{module_name}.te"
        fc_path = self.modules_dir / f"{module_name}.fc"

        try:
            with open(te_path, 'w') as f:
                f.write(te_content)
            with open(fc_path, 'w') as f:
                f.write(fc_content)
            logger.info(f"Wrote SELinux policy to {te_path}")
            return te_path, fc_path
        except Exception as e:
            logger.error(f"Failed to write SELinux policy: {e}")
            raise

    def compile_policy(self, module_name: str) -> Tuple[bool, str]:
        """Compile SELinux policy module."""
        te_path = self.modules_dir / f"{module_name}.te"
        mod_path = self.modules_dir / f"{module_name}.mod"
        pp_path = self.modules_dir / f"{module_name}.pp"

        try:
            # Compile to .mod
            result = subprocess.run(
                ['checkmodule', '-M', '-m', '-o', str(mod_path), str(te_path)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                return False, f"checkmodule failed: {result.stderr}"

            # Package to .pp
            result = subprocess.run(
                ['semodule_package', '-o', str(pp_path), '-m', str(mod_path)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                return False, f"semodule_package failed: {result.stderr}"

            return True, str(pp_path)
        except FileNotFoundError as e:
            return False, f"SELinux tools not found: {e}"
        except Exception as e:
            return False, str(e)

    def load_policy(self, module_name: str) -> Tuple[bool, str]:
        """Load SELinux policy module."""
        pp_path = self.modules_dir / f"{module_name}.pp"

        try:
            result = subprocess.run(
                ['semodule', '-i', str(pp_path)],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode == 0:
                return True, "Policy loaded successfully"
            return False, result.stderr
        except Exception as e:
            return False, str(e)

    def unload_policy(self, module_name: str) -> Tuple[bool, str]:
        """Unload SELinux policy module."""
        try:
            result = subprocess.run(
                ['semodule', '-r', module_name],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode == 0:
                return True, "Policy unloaded successfully"
            return False, result.stderr
        except Exception as e:
            return False, str(e)


class MACProfileGenerator:
    """
    Unified MAC profile generator supporting both AppArmor and SELinux.

    Auto-detects the active MAC system and generates appropriate profiles.
    """

    def __init__(self):
        self._mac_system = self._detect_mac_system()
        self._apparmor = AppArmorProfileGenerator()
        self._selinux = SELinuxPolicyGenerator()
        self._applied_profiles: Dict[str, str] = {}
        self._lock = threading.Lock()

        logger.info(f"MAC Profile Generator initialized (system: {self._mac_system.value})")

    def _detect_mac_system(self) -> MACSystem:
        """Detect which MAC system is active."""
        # Check for AppArmor
        if os.path.exists('/sys/kernel/security/apparmor'):
            try:
                with open('/sys/kernel/security/apparmor/profiles', 'r') as f:
                    if f.read().strip():
                        return MACSystem.APPARMOR
            except Exception:
                pass

        # Check for SELinux
        if os.path.exists('/sys/fs/selinux'):
            try:
                with open('/sys/fs/selinux/enforce', 'r') as f:
                    return MACSystem.SELINUX
            except Exception:
                pass

        return MACSystem.NONE

    @property
    def mac_system(self) -> MACSystem:
        """Get the detected MAC system."""
        return self._mac_system

    def is_available(self) -> bool:
        """Check if a MAC system is available."""
        return self._mac_system != MACSystem.NONE

    def generate_apparmor_profile(
        self,
        sandbox_id: str,
        sandbox_profile: Any,
    ) -> str:
        """Generate AppArmor profile for a sandbox."""
        config = MACProfileConfig.from_sandbox_profile(sandbox_id, sandbox_profile)
        return self._apparmor.generate_profile(config)

    def generate_selinux_policy(
        self,
        sandbox_id: str,
        sandbox_profile: Any,
    ) -> Tuple[str, str]:
        """Generate SELinux policy for a sandbox."""
        config = MACProfileConfig.from_sandbox_profile(sandbox_id, sandbox_profile)
        return self._selinux.generate_policy(config)

    def apply_profile(
        self,
        sandbox_id: str,
        sandbox_profile: Any,
        mode: ProfileMode = ProfileMode.ENFORCE,
    ) -> Tuple[bool, str]:
        """Apply MAC profile for a sandbox."""
        with self._lock:
            if self._mac_system == MACSystem.APPARMOR:
                return self._apply_apparmor(sandbox_id, sandbox_profile, mode)
            elif self._mac_system == MACSystem.SELINUX:
                return self._apply_selinux(sandbox_id, sandbox_profile, mode)
            else:
                return False, "No MAC system available"

    def _apply_apparmor(
        self,
        sandbox_id: str,
        sandbox_profile: Any,
        mode: ProfileMode,
    ) -> Tuple[bool, str]:
        """Apply AppArmor profile."""
        try:
            config = MACProfileConfig.from_sandbox_profile(sandbox_id, sandbox_profile)
            config.mode = mode

            # Generate profile
            profile_content = self._apparmor.generate_profile(config)

            # Write profile
            self._apparmor.write_profile(config, profile_content)

            # Load profile
            success, message = self._apparmor.load_profile(config.profile_name)

            if success:
                self._applied_profiles[sandbox_id] = config.profile_name

            return success, message
        except Exception as e:
            return False, str(e)

    def _apply_selinux(
        self,
        sandbox_id: str,
        sandbox_profile: Any,
        mode: ProfileMode,
    ) -> Tuple[bool, str]:
        """Apply SELinux policy."""
        try:
            config = MACProfileConfig.from_sandbox_profile(sandbox_id, sandbox_profile)

            # Generate policy
            te_content, fc_content = self._selinux.generate_policy(config)

            # Write policy files
            self._selinux.write_policy(config, te_content, fc_content)

            # Compile policy
            module_name = f"boundary_sandbox_{sandbox_id.replace('-', '_')}"
            success, message = self._selinux.compile_policy(module_name)

            if not success:
                return False, message

            # Load policy
            success, message = self._selinux.load_policy(module_name)

            if success:
                self._applied_profiles[sandbox_id] = module_name

            return success, message
        except Exception as e:
            return False, str(e)

    def remove_profile(self, sandbox_id: str) -> Tuple[bool, str]:
        """Remove MAC profile for a sandbox."""
        with self._lock:
            profile_name = self._applied_profiles.get(sandbox_id)
            if not profile_name:
                return True, "No profile to remove"

            if self._mac_system == MACSystem.APPARMOR:
                success, message = self._apparmor.unload_profile(profile_name)
            elif self._mac_system == MACSystem.SELINUX:
                success, message = self._selinux.unload_policy(profile_name)
            else:
                return False, "No MAC system available"

            if success:
                del self._applied_profiles[sandbox_id]

            return success, message

    def get_profile_name(self, sandbox_id: str) -> Optional[str]:
        """Get the profile name for a sandbox."""
        return self._applied_profiles.get(sandbox_id)

    def list_applied_profiles(self) -> Dict[str, str]:
        """List all applied profiles."""
        return dict(self._applied_profiles)

    def get_capabilities(self) -> Dict[str, Any]:
        """Get MAC capabilities info."""
        return {
            'mac_system': self._mac_system.value,
            'available': self.is_available(),
            'applied_profiles': len(self._applied_profiles),
            'apparmor_available': os.path.exists('/sys/kernel/security/apparmor'),
            'selinux_available': os.path.exists('/sys/fs/selinux'),
        }


# Global generator instance
_global_generator: Optional[MACProfileGenerator] = None
_generator_lock = threading.Lock()


def get_mac_generator() -> MACProfileGenerator:
    """Get the global MAC profile generator."""
    global _global_generator

    if _global_generator is None:
        with _generator_lock:
            if _global_generator is None:
                _global_generator = MACProfileGenerator()

    return _global_generator


if __name__ == '__main__':
    print("Testing MAC Profile Generator...")

    generator = get_mac_generator()
    print(f"Detected MAC system: {generator.mac_system.value}")
    print(f"Available: {generator.is_available()}")

    # Create a mock sandbox profile
    class MockProfile:
        name = "RESTRICTED"
        network_policy = None

    # Generate AppArmor profile
    print("\n=== AppArmor Profile ===")
    profile = generator.generate_apparmor_profile("test-001", MockProfile())
    print(profile[:1000] + "...")

    # Generate SELinux policy
    print("\n=== SELinux Policy ===")
    te, fc = generator.generate_selinux_policy("test-001", MockProfile())
    print(te[:1000] + "...")

    print("\nCapabilities:", generator.get_capabilities())
    print("\nMAC Profile Generator test complete.")
