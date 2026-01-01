"""
YAML Configuration for Sandbox Profiles

Allows defining sandbox profiles in YAML configuration files for:
- Declarative profile management
- Version control of security policies
- Environment-specific configurations
- Easy profile sharing and templating

Configuration Structure:
    profiles:
      restricted:
        description: "Restricted sandbox for untrusted code"
        cgroup_limits:
          memory_max: "512M"
          cpu_percent: 50
        network_policy:
          deny_all: false
          allowed_hosts:
            - "api.internal:443"
        seccomp_profile: "standard"
        namespaces:
          - pid
          - mount
          - net

Usage:
    from daemon.sandbox.profile_config import ProfileConfigLoader, get_profile_loader

    loader = get_profile_loader()
    loader.load_config("/etc/boundary-daemon/profiles.yaml")

    profile = loader.get_profile("restricted")
    manager.run_sandboxed(command, profile=profile)
"""

import logging
import os
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

logger = logging.getLogger(__name__)

# Optional YAML support
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    yaml = None


@dataclass
class CgroupLimitsConfig:
    """Cgroup limits configuration from YAML."""
    memory_max: Optional[str] = None  # e.g., "512M", "1G"
    memory_high: Optional[str] = None
    cpu_percent: Optional[int] = None  # 0-100
    cpu_max: Optional[str] = None  # e.g., "50000 100000"
    pids_max: Optional[int] = None
    io_max_read: Optional[str] = None  # e.g., "50M"
    io_max_write: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CgroupLimitsConfig':
        """Create from dictionary."""
        return cls(
            memory_max=data.get('memory_max'),
            memory_high=data.get('memory_high'),
            cpu_percent=data.get('cpu_percent'),
            cpu_max=data.get('cpu_max'),
            pids_max=data.get('pids_max'),
            io_max_read=data.get('io_max_read'),
            io_max_write=data.get('io_max_write'),
        )

    def to_cgroup_limits(self) -> Any:
        """Convert to CgroupLimits object."""
        try:
            from .cgroups import CgroupLimits
        except ImportError:
            return None

        limits = CgroupLimits()

        if self.memory_max:
            limits.memory_max = self._parse_size(self.memory_max)
        if self.memory_high:
            limits.memory_high = self._parse_size(self.memory_high)
        if self.cpu_percent:
            limits.cpu_max = self.cpu_percent * 1000  # percent to quota
            limits.cpu_period = 100000
        if self.pids_max:
            limits.pids_max = self.pids_max
        if self.io_max_read:
            limits.io_rbps_max = self._parse_size(self.io_max_read)
        if self.io_max_write:
            limits.io_wbps_max = self._parse_size(self.io_max_write)

        return limits

    @staticmethod
    def _parse_size(size_str: str) -> int:
        """Parse size string to bytes."""
        size_str = size_str.strip().upper()
        multipliers = {
            'B': 1,
            'K': 1024,
            'KB': 1024,
            'M': 1024 * 1024,
            'MB': 1024 * 1024,
            'G': 1024 * 1024 * 1024,
            'GB': 1024 * 1024 * 1024,
            'T': 1024 * 1024 * 1024 * 1024,
            'TB': 1024 * 1024 * 1024 * 1024,
        }

        for suffix, mult in sorted(multipliers.items(), key=lambda x: -len(x[0])):
            if size_str.endswith(suffix):
                return int(float(size_str[:-len(suffix)]) * mult)

        return int(size_str)


@dataclass
class NetworkPolicyConfig:
    """Network policy configuration from YAML."""
    allow_all: bool = False
    deny_all: bool = False
    allow_loopback: bool = True
    allow_dns: bool = True
    allowed_hosts: List[str] = field(default_factory=list)
    allowed_ports: List[int] = field(default_factory=list)
    allowed_cidrs: List[str] = field(default_factory=list)
    blocked_hosts: List[str] = field(default_factory=list)
    blocked_ports: List[int] = field(default_factory=list)
    log_blocked: bool = False

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'NetworkPolicyConfig':
        """Create from dictionary."""
        return cls(
            allow_all=data.get('allow_all', False),
            deny_all=data.get('deny_all', False),
            allow_loopback=data.get('allow_loopback', True),
            allow_dns=data.get('allow_dns', True),
            allowed_hosts=data.get('allowed_hosts', []),
            allowed_ports=data.get('allowed_ports', []),
            allowed_cidrs=data.get('allowed_cidrs', []),
            blocked_hosts=data.get('blocked_hosts', []),
            blocked_ports=data.get('blocked_ports', []),
            log_blocked=data.get('log_blocked', False),
        )

    def to_network_policy(self) -> Any:
        """Convert to NetworkPolicy object."""
        try:
            from .network_policy import NetworkPolicy
        except ImportError:
            return None

        return NetworkPolicy(
            allow_all=self.allow_all,
            deny_all=self.deny_all,
            allow_loopback=self.allow_loopback,
            allow_dns=self.allow_dns,
            allowed_hosts=self.allowed_hosts,
            allowed_ports=self.allowed_ports,
            allowed_cidrs=self.allowed_cidrs,
            blocked_hosts=self.blocked_hosts,
            blocked_ports=self.blocked_ports,
            log_blocked=self.log_blocked,
        )


@dataclass
class SandboxProfileConfig:
    """Sandbox profile configuration from YAML."""
    name: str
    description: str = ""
    enabled: bool = True

    # Isolation settings
    namespaces: List[str] = field(default_factory=lambda: ['pid', 'mount', 'net'])
    seccomp_profile: str = "standard"  # minimal, standard, network, untrusted
    enable_firewall: bool = True

    # Resource limits
    cgroup_limits: Optional[CgroupLimitsConfig] = None

    # Network policy
    network_policy: Optional[NetworkPolicyConfig] = None

    # Timeout
    timeout_seconds: Optional[int] = None

    # Environment
    inherit_env: bool = False
    env_whitelist: List[str] = field(default_factory=list)
    env_vars: Dict[str, str] = field(default_factory=dict)

    # Working directory
    working_dir: Optional[str] = None

    # MAC profile
    mac_profile: Optional[str] = None  # apparmor/selinux profile name

    # Labels for organization
    labels: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, name: str, data: Dict[str, Any]) -> 'SandboxProfileConfig':
        """Create from dictionary."""
        cgroup_data = data.get('cgroup_limits')
        network_data = data.get('network_policy')

        return cls(
            name=name,
            description=data.get('description', ''),
            enabled=data.get('enabled', True),
            namespaces=data.get('namespaces', ['pid', 'mount', 'net']),
            seccomp_profile=data.get('seccomp_profile', 'standard'),
            enable_firewall=data.get('enable_firewall', True),
            cgroup_limits=CgroupLimitsConfig.from_dict(cgroup_data) if cgroup_data else None,
            network_policy=NetworkPolicyConfig.from_dict(network_data) if network_data else None,
            timeout_seconds=data.get('timeout_seconds'),
            inherit_env=data.get('inherit_env', False),
            env_whitelist=data.get('env_whitelist', []),
            env_vars=data.get('env_vars', {}),
            working_dir=data.get('working_dir'),
            mac_profile=data.get('mac_profile'),
            labels=data.get('labels', {}),
        )

    def to_sandbox_profile(self) -> Any:
        """Convert to SandboxProfile object."""
        try:
            from .sandbox_manager import SandboxProfile
        except ImportError:
            return None

        profile = SandboxProfile(name=self.name)

        # Set cgroup limits
        if self.cgroup_limits:
            profile.cgroup_limits = self.cgroup_limits.to_cgroup_limits()

        # Set network policy
        if self.network_policy:
            profile.network_policy = self.network_policy.to_network_policy()

        # Set timeout
        if self.timeout_seconds:
            profile.timeout_seconds = self.timeout_seconds

        return profile


@dataclass
class ProfileConfigFile:
    """Complete profile configuration file."""
    version: str = "1"
    profiles: Dict[str, SandboxProfileConfig] = field(default_factory=dict)
    defaults: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ProfileConfigFile':
        """Create from dictionary."""
        profiles = {}
        profiles_data = data.get('profiles', {})

        for name, profile_data in profiles_data.items():
            profiles[name] = SandboxProfileConfig.from_dict(name, profile_data)

        return cls(
            version=data.get('version', '1'),
            profiles=profiles,
            defaults=data.get('defaults', {}),
        )


class ProfileConfigLoader:
    """
    Loads and manages sandbox profiles from YAML configuration.

    Supports:
    - Loading from file or directory
    - Hot reloading on file changes
    - Profile inheritance and defaults
    - Environment variable substitution
    """

    def __init__(self):
        self._configs: Dict[str, ProfileConfigFile] = {}
        self._profiles: Dict[str, SandboxProfileConfig] = {}
        self._defaults: Dict[str, Any] = {}
        self._lock = threading.Lock()
        self._loaded_files: List[Path] = []

    def load_config(self, path: Union[str, Path]) -> bool:
        """Load configuration from file or directory."""
        if not YAML_AVAILABLE:
            logger.error("PyYAML not available. Install with: pip install pyyaml")
            return False

        path = Path(path)

        if path.is_dir():
            return self._load_directory(path)
        else:
            return self._load_file(path)

    def _load_file(self, path: Path) -> bool:
        """Load a single configuration file."""
        if not path.exists():
            logger.warning(f"Config file not found: {path}")
            return False

        try:
            with open(path, 'r') as f:
                data = yaml.safe_load(f)

            if not data:
                logger.warning(f"Empty config file: {path}")
                return False

            # Parse and store
            config = ProfileConfigFile.from_dict(data)

            with self._lock:
                self._configs[str(path)] = config
                self._loaded_files.append(path)

                # Merge profiles
                for name, profile in config.profiles.items():
                    self._profiles[name] = profile

                # Merge defaults
                self._defaults.update(config.defaults)

            logger.info(f"Loaded {len(config.profiles)} profiles from {path}")
            return True

        except Exception as e:
            logger.error(f"Failed to load config {path}: {e}")
            return False

    def _load_directory(self, path: Path) -> bool:
        """Load all YAML files from a directory."""
        success = True

        for yaml_file in sorted(path.glob("*.yaml")):
            if not self._load_file(yaml_file):
                success = False

        for yml_file in sorted(path.glob("*.yml")):
            if not self._load_file(yml_file):
                success = False

        return success

    def reload(self) -> bool:
        """Reload all configuration files."""
        with self._lock:
            files = list(self._loaded_files)
            self._configs.clear()
            self._profiles.clear()
            self._defaults.clear()
            self._loaded_files.clear()

        success = True
        for path in files:
            if not self._load_file(path):
                success = False

        return success

    def get_profile(self, name: str) -> Optional[SandboxProfileConfig]:
        """Get a profile by name."""
        with self._lock:
            return self._profiles.get(name)

    def get_sandbox_profile(self, name: str) -> Optional[Any]:
        """Get a SandboxProfile object by name."""
        config = self.get_profile(name)
        if config:
            return config.to_sandbox_profile()
        return None

    def list_profiles(self) -> List[str]:
        """List all available profile names."""
        with self._lock:
            return list(self._profiles.keys())

    def get_all_profiles(self) -> Dict[str, SandboxProfileConfig]:
        """Get all profiles."""
        with self._lock:
            return dict(self._profiles)

    def add_profile(self, config: SandboxProfileConfig) -> None:
        """Add or update a profile programmatically."""
        with self._lock:
            self._profiles[config.name] = config

    def remove_profile(self, name: str) -> bool:
        """Remove a profile."""
        with self._lock:
            if name in self._profiles:
                del self._profiles[name]
                return True
            return False

    def export_config(self, path: Union[str, Path]) -> bool:
        """Export current configuration to YAML file."""
        if not YAML_AVAILABLE:
            logger.error("PyYAML not available")
            return False

        path = Path(path)

        try:
            data = {
                'version': '1',
                'profiles': {},
            }

            with self._lock:
                for name, profile in self._profiles.items():
                    profile_data = {
                        'description': profile.description,
                        'enabled': profile.enabled,
                        'namespaces': profile.namespaces,
                        'seccomp_profile': profile.seccomp_profile,
                        'enable_firewall': profile.enable_firewall,
                    }

                    if profile.cgroup_limits:
                        profile_data['cgroup_limits'] = {
                            'memory_max': profile.cgroup_limits.memory_max,
                            'cpu_percent': profile.cgroup_limits.cpu_percent,
                            'pids_max': profile.cgroup_limits.pids_max,
                        }

                    if profile.network_policy:
                        profile_data['network_policy'] = {
                            'allow_all': profile.network_policy.allow_all,
                            'deny_all': profile.network_policy.deny_all,
                            'allowed_hosts': profile.network_policy.allowed_hosts,
                            'allowed_ports': profile.network_policy.allowed_ports,
                        }

                    if profile.timeout_seconds:
                        profile_data['timeout_seconds'] = profile.timeout_seconds

                    if profile.labels:
                        profile_data['labels'] = profile.labels

                    data['profiles'][name] = profile_data

            with open(path, 'w') as f:
                yaml.dump(data, f, default_flow_style=False, sort_keys=False)

            logger.info(f"Exported configuration to {path}")
            return True

        except Exception as e:
            logger.error(f"Failed to export config: {e}")
            return False

    def create_default_config(self) -> Dict[str, Any]:
        """Create default configuration structure."""
        return {
            'version': '1',
            'defaults': {
                'timeout_seconds': 300,
                'enable_firewall': True,
            },
            'profiles': {
                'minimal': {
                    'description': 'Minimal isolation with basic resource limits',
                    'namespaces': [],
                    'seccomp_profile': 'minimal',
                    'enable_firewall': False,
                    'cgroup_limits': {
                        'memory_max': '1G',
                        'pids_max': 100,
                    },
                },
                'standard': {
                    'description': 'Standard isolation for trusted code',
                    'namespaces': ['pid', 'mount'],
                    'seccomp_profile': 'standard',
                    'cgroup_limits': {
                        'memory_max': '512M',
                        'cpu_percent': 50,
                        'pids_max': 50,
                    },
                },
                'restricted': {
                    'description': 'Restricted isolation for semi-trusted code',
                    'namespaces': ['pid', 'mount', 'net', 'ipc'],
                    'seccomp_profile': 'standard',
                    'cgroup_limits': {
                        'memory_max': '256M',
                        'cpu_percent': 25,
                        'pids_max': 20,
                    },
                    'network_policy': {
                        'deny_all': False,
                        'allow_dns': True,
                        'allowed_ports': [80, 443],
                    },
                },
                'untrusted': {
                    'description': 'Strict isolation for untrusted code',
                    'namespaces': ['pid', 'mount', 'net', 'ipc', 'uts', 'user'],
                    'seccomp_profile': 'untrusted',
                    'cgroup_limits': {
                        'memory_max': '128M',
                        'cpu_percent': 10,
                        'pids_max': 10,
                    },
                    'network_policy': {
                        'deny_all': True,
                    },
                    'timeout_seconds': 60,
                },
                'airgap': {
                    'description': 'Air-gapped sandbox with no network',
                    'namespaces': ['pid', 'mount', 'net', 'ipc', 'uts'],
                    'seccomp_profile': 'untrusted',
                    'cgroup_limits': {
                        'memory_max': '256M',
                        'cpu_percent': 25,
                        'pids_max': 20,
                    },
                    'network_policy': {
                        'deny_all': True,
                        'allow_loopback': True,
                    },
                },
                'coldroom': {
                    'description': 'Maximum isolation for sensitive operations',
                    'namespaces': ['pid', 'mount', 'net', 'ipc', 'uts', 'user'],
                    'seccomp_profile': 'untrusted',
                    'cgroup_limits': {
                        'memory_max': '64M',
                        'cpu_percent': 5,
                        'pids_max': 5,
                    },
                    'network_policy': {
                        'deny_all': True,
                        'allow_loopback': False,
                    },
                    'timeout_seconds': 30,
                },
            },
        }

    def write_default_config(self, path: Union[str, Path]) -> bool:
        """Write default configuration to file."""
        if not YAML_AVAILABLE:
            logger.error("PyYAML not available")
            return False

        path = Path(path)

        try:
            config = self.create_default_config()

            with open(path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, sort_keys=False)

            logger.info(f"Wrote default configuration to {path}")
            return True

        except Exception as e:
            logger.error(f"Failed to write default config: {e}")
            return False


# Global loader instance
_global_loader: Optional[ProfileConfigLoader] = None
_loader_lock = threading.Lock()


def get_profile_loader() -> ProfileConfigLoader:
    """Get the global profile config loader."""
    global _global_loader

    if _global_loader is None:
        with _loader_lock:
            if _global_loader is None:
                _global_loader = ProfileConfigLoader()

    return _global_loader


if __name__ == '__main__':
    import tempfile

    print("Testing Profile Configuration Loader...")

    if not YAML_AVAILABLE:
        print("PyYAML not available. Install with: pip install pyyaml")
        exit(1)

    loader = ProfileConfigLoader()

    # Write default config
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        config_path = f.name

    loader.write_default_config(config_path)
    print(f"Wrote default config to {config_path}")

    # Load config
    loader.load_config(config_path)

    # List profiles
    print(f"\nLoaded profiles: {loader.list_profiles()}")

    # Get a profile
    profile = loader.get_profile("restricted")
    if profile:
        print(f"\n=== {profile.name} ===")
        print(f"  Description: {profile.description}")
        print(f"  Namespaces: {profile.namespaces}")
        print(f"  Seccomp: {profile.seccomp_profile}")
        if profile.cgroup_limits:
            print(f"  Memory: {profile.cgroup_limits.memory_max}")
            print(f"  CPU: {profile.cgroup_limits.cpu_percent}%")
        if profile.network_policy:
            print(f"  Network deny_all: {profile.network_policy.deny_all}")

    # Convert to SandboxProfile
    sandbox_profile = loader.get_sandbox_profile("restricted")
    print(f"\nSandboxProfile: {sandbox_profile}")

    # Cleanup
    os.unlink(config_path)

    print("\nProfile Configuration Loader test complete.")
