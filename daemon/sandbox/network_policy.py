"""
Per-Sandbox Network Policy for Boundary Daemon

Provides fine-grained network control for sandboxed processes using:
- iptables/nftables with cgroup matching (--cgroup flag)
- Network namespace isolation (fallback)
- Defense in depth (both when available)

This module integrates with:
- daemon/enforcement/network_enforcer.py (system-wide rules)
- daemon/sandbox/sandbox_manager.py (per-sandbox rules)
- daemon/sandbox/cgroups.py (cgroup path for matching)

Usage:
    policy = NetworkPolicy(
        allowed_hosts=["api.internal:443", "10.0.0.0/8"],
        allowed_ports=[443, 8443],
        allow_dns=True,
        allow_loopback=True,
    )

    sandbox = manager.create_sandbox(
        name="api-worker",
        network_policy=policy,
    )

Cgroup matching allows per-sandbox rules:
    iptables -A OUTPUT -m cgroup --path /boundary-daemon/sandbox-1 -j SANDBOX_1
"""

import logging
import os
import shutil
import subprocess
import threading
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

logger = logging.getLogger(__name__)


class FirewallBackend(Enum):
    """Available firewall backends."""
    IPTABLES = "iptables"
    NFTABLES = "nftables"
    NONE = "none"


class NetworkAction(Enum):
    """Action to take on matching traffic."""
    ALLOW = auto()
    DENY = auto()
    LOG = auto()
    LOG_AND_DENY = auto()


@dataclass
class HostRule:
    """A rule for a specific host/network."""
    host: str  # IP, CIDR, or hostname
    port: Optional[int] = None
    protocol: str = "tcp"
    action: NetworkAction = NetworkAction.ALLOW

    def to_iptables_args(self) -> List[str]:
        """Convert to iptables arguments."""
        args = []

        # Handle CIDR notation
        if '/' in self.host:
            args.extend(['-d', self.host])
        else:
            args.extend(['-d', self.host])

        args.extend(['-p', self.protocol])

        if self.port:
            args.extend(['--dport', str(self.port)])

        return args


@dataclass
class NetworkPolicy:
    """
    Network policy for a sandbox.

    Defines what network access a sandboxed process is allowed.
    """
    # Basic controls
    allow_all: bool = False  # If True, no restrictions
    deny_all: bool = False  # If True, block everything

    # Loopback
    allow_loopback: bool = True

    # DNS
    allow_dns: bool = True
    dns_servers: List[str] = field(default_factory=lambda: ["8.8.8.8", "8.8.4.4"])

    # Allowed destinations
    allowed_hosts: List[str] = field(default_factory=list)  # ["host:port", "10.0.0.0/8"]
    allowed_ports: List[int] = field(default_factory=list)  # [443, 8080]
    allowed_cidrs: List[str] = field(default_factory=list)  # ["10.0.0.0/8"]

    # Blocked destinations (takes precedence)
    blocked_hosts: List[str] = field(default_factory=list)
    blocked_ports: List[int] = field(default_factory=list)
    blocked_cidrs: List[str] = field(default_factory=list)

    # Protocol controls
    allow_icmp: bool = False
    allow_udp: bool = True
    allow_raw: bool = False

    # Egress rate limiting
    rate_limit_kbps: Optional[int] = None
    rate_limit_pps: Optional[int] = None  # Packets per second

    # Logging
    log_blocked: bool = True
    log_prefix: str = "[SANDBOX-BLOCKED]"

    @classmethod
    def allow_none(cls) -> 'NetworkPolicy':
        """No network access allowed."""
        return cls(
            deny_all=True,
            allow_loopback=True,
            allow_dns=False,
        )

    @classmethod
    def loopback_only(cls) -> 'NetworkPolicy':
        """Only loopback allowed."""
        return cls(
            deny_all=True,
            allow_loopback=True,
            allow_dns=False,
        )

    @classmethod
    def internal_only(cls, internal_cidrs: Optional[List[str]] = None) -> 'NetworkPolicy':
        """Only internal network allowed."""
        return cls(
            allow_loopback=True,
            allow_dns=True,
            allowed_cidrs=internal_cidrs or ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
            blocked_cidrs=["0.0.0.0/0"],  # Block internet
        )

    @classmethod
    def unrestricted(cls) -> 'NetworkPolicy':
        """No restrictions (use namespace isolation only)."""
        return cls(allow_all=True)

    @classmethod
    def for_boundary_mode(cls, mode: int) -> 'NetworkPolicy':
        """
        Get appropriate policy for a boundary mode.

        Args:
            mode: Boundary mode (0=OPEN to 5=LOCKDOWN)
        """
        if mode >= 5:  # LOCKDOWN
            return cls(
                deny_all=True,
                allow_loopback=False,
                allow_dns=False,
            )
        elif mode >= 4:  # COLDROOM
            return cls.loopback_only()
        elif mode >= 3:  # AIRGAP
            return cls.loopback_only()
        elif mode >= 2:  # TRUSTED
            return cls.internal_only()
        elif mode >= 1:  # RESTRICTED
            return cls(
                allow_loopback=True,
                allow_dns=True,
                log_blocked=True,
            )
        else:  # OPEN
            return cls.unrestricted()


class SandboxFirewall:
    """
    Manages per-sandbox firewall rules.

    Uses iptables/nftables with cgroup matching to apply rules
    only to processes within a specific sandbox's cgroup.

    Defense in depth:
    1. Network namespace isolation (if available)
    2. iptables/nftables rules (if available)
    3. Seccomp filtering of socket syscalls (last resort)
    """

    # Chain prefix for sandbox rules
    CHAIN_PREFIX = "SANDBOX_"

    # nftables table for sandbox rules
    NFT_TABLE = "sandbox_firewall"

    def __init__(self):
        self._backend = self._detect_backend()
        self._has_cgroup_match = self._check_cgroup_match()
        self._lock = threading.Lock()
        self._active_sandboxes: Dict[str, Path] = {}  # sandbox_id -> cgroup_path
        self._has_root = os.geteuid() == 0 if os.name == 'posix' else False

    def _detect_backend(self) -> FirewallBackend:
        """Detect available firewall backend."""
        if os.name != 'posix':
            return FirewallBackend.NONE

        # Check for nftables
        if shutil.which('nft'):
            try:
                result = subprocess.run(
                    ['nft', 'list', 'tables'],
                    capture_output=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    return FirewallBackend.NFTABLES
            except (subprocess.TimeoutExpired, OSError):
                pass

        # Check for iptables
        if shutil.which('iptables'):
            try:
                result = subprocess.run(
                    ['iptables', '-L', '-n'],
                    capture_output=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    return FirewallBackend.IPTABLES
            except (subprocess.TimeoutExpired, OSError):
                pass

        return FirewallBackend.NONE

    def _check_cgroup_match(self) -> bool:
        """Check if iptables cgroup matching is available."""
        if self._backend != FirewallBackend.IPTABLES:
            return self._backend == FirewallBackend.NFTABLES  # nftables has native cgroup support

        try:
            # Try to load the cgroup match module
            result = subprocess.run(
                ['iptables', '-m', 'cgroup', '--help'],
                capture_output=True,
                timeout=5,
            )
            return b'cgroup' in result.stdout or b'cgroup' in result.stderr
        except (subprocess.TimeoutExpired, OSError):
            return False

    @property
    def is_available(self) -> bool:
        """Check if firewall management is available."""
        return self._backend != FirewallBackend.NONE and self._has_root

    @property
    def has_cgroup_match(self) -> bool:
        """Check if cgroup matching is available for per-sandbox rules."""
        return self._has_cgroup_match and self._has_root

    def get_capabilities(self) -> Dict[str, Any]:
        """Get firewall capabilities."""
        return {
            'backend': self._backend.value,
            'available': self.is_available,
            'cgroup_match': self.has_cgroup_match,
            'has_root': self._has_root,
        }

    def setup_sandbox_rules(
        self,
        sandbox_id: str,
        cgroup_path: Path,
        policy: NetworkPolicy,
    ) -> Tuple[bool, str]:
        """
        Set up firewall rules for a sandbox.

        Args:
            sandbox_id: Unique sandbox identifier
            cgroup_path: Path to sandbox's cgroup
            policy: Network policy to apply

        Returns:
            (success, message)
        """
        if not self.is_available:
            return False, "Firewall not available"

        if policy.allow_all:
            logger.debug(f"Sandbox {sandbox_id}: allow_all policy, no rules needed")
            return True, "No rules needed (allow_all)"

        with self._lock:
            try:
                if self._backend == FirewallBackend.IPTABLES:
                    self._setup_iptables_rules(sandbox_id, cgroup_path, policy)
                else:
                    self._setup_nftables_rules(sandbox_id, cgroup_path, policy)

                self._active_sandboxes[sandbox_id] = cgroup_path
                logger.info(f"Firewall rules set for sandbox {sandbox_id}")
                return True, "Rules applied"

            except Exception as e:
                logger.error(f"Failed to setup firewall for {sandbox_id}: {e}")
                return False, str(e)

    def _setup_iptables_rules(
        self,
        sandbox_id: str,
        cgroup_path: Path,
        policy: NetworkPolicy,
    ) -> None:
        """Set up iptables rules for a sandbox."""
        chain_name = f"{self.CHAIN_PREFIX}{sandbox_id.replace('-', '_').upper()}"

        # Create chain
        self._run_iptables(['-N', chain_name], ignore_errors=True)
        self._run_iptables(['-F', chain_name], ignore_errors=True)

        # Add jump from OUTPUT with cgroup match
        if self._has_cgroup_match:
            # Get relative cgroup path
            cgroup_rel = str(cgroup_path).replace('/sys/fs/cgroup', '')
            self._run_iptables([
                '-I', 'OUTPUT',
                '-m', 'cgroup', '--path', cgroup_rel,
                '-j', chain_name,
            ], ignore_errors=True)

        # Build rules based on policy
        if policy.deny_all:
            # Allow loopback if permitted
            if policy.allow_loopback:
                self._run_iptables(['-A', chain_name, '-o', 'lo', '-j', 'ACCEPT'])

            # Allow DNS if permitted
            if policy.allow_dns:
                for dns in policy.dns_servers:
                    self._run_iptables([
                        '-A', chain_name,
                        '-d', dns, '-p', 'udp', '--dport', '53',
                        '-j', 'ACCEPT',
                    ])
                    self._run_iptables([
                        '-A', chain_name,
                        '-d', dns, '-p', 'tcp', '--dport', '53',
                        '-j', 'ACCEPT',
                    ])

            # Allow established connections
            self._run_iptables([
                '-A', chain_name,
                '-m', 'state', '--state', 'ESTABLISHED,RELATED',
                '-j', 'ACCEPT',
            ])

            # Log and drop everything else
            if policy.log_blocked:
                self._run_iptables([
                    '-A', chain_name,
                    '-j', 'LOG',
                    '--log-prefix', f'{policy.log_prefix} ',
                    '--log-level', '4',
                ])

            self._run_iptables(['-A', chain_name, '-j', 'DROP'])
            return

        # More nuanced policy
        # 1. Always allow loopback if permitted
        if policy.allow_loopback:
            self._run_iptables(['-A', chain_name, '-o', 'lo', '-j', 'ACCEPT'])

        # 2. Allow established connections
        self._run_iptables([
            '-A', chain_name,
            '-m', 'state', '--state', 'ESTABLISHED,RELATED',
            '-j', 'ACCEPT',
        ])

        # 3. Allow DNS if permitted
        if policy.allow_dns:
            for dns in policy.dns_servers:
                self._run_iptables([
                    '-A', chain_name,
                    '-d', dns, '-p', 'udp', '--dport', '53',
                    '-j', 'ACCEPT',
                ])

        # 4. Block explicitly blocked destinations first
        for host in policy.blocked_hosts:
            host_part, port_part = self._parse_host_port(host)
            args = ['-A', chain_name, '-d', host_part]
            if port_part:
                args.extend(['-p', 'tcp', '--dport', str(port_part)])
            args.extend(['-j', 'DROP'])
            self._run_iptables(args)

        for port in policy.blocked_ports:
            self._run_iptables([
                '-A', chain_name, '-p', 'tcp', '--dport', str(port), '-j', 'DROP',
            ])
            self._run_iptables([
                '-A', chain_name, '-p', 'udp', '--dport', str(port), '-j', 'DROP',
            ])

        for cidr in policy.blocked_cidrs:
            self._run_iptables(['-A', chain_name, '-d', cidr, '-j', 'DROP'])

        # 5. Allow explicitly allowed destinations
        for host in policy.allowed_hosts:
            host_part, port_part = self._parse_host_port(host)
            args = ['-A', chain_name, '-d', host_part]
            if port_part:
                args.extend(['-p', 'tcp', '--dport', str(port_part)])
            args.extend(['-j', 'ACCEPT'])
            self._run_iptables(args)

        for port in policy.allowed_ports:
            self._run_iptables([
                '-A', chain_name, '-p', 'tcp', '--dport', str(port), '-j', 'ACCEPT',
            ])
            if policy.allow_udp:
                self._run_iptables([
                    '-A', chain_name, '-p', 'udp', '--dport', str(port), '-j', 'ACCEPT',
                ])

        for cidr in policy.allowed_cidrs:
            self._run_iptables(['-A', chain_name, '-d', cidr, '-j', 'ACCEPT'])

        # 6. ICMP
        if policy.allow_icmp:
            self._run_iptables(['-A', chain_name, '-p', 'icmp', '-j', 'ACCEPT'])

        # 7. Default action: log and drop if not allow_all
        if policy.log_blocked:
            self._run_iptables([
                '-A', chain_name,
                '-j', 'LOG',
                '--log-prefix', f'{policy.log_prefix} ',
                '--log-level', '4',
            ])

        self._run_iptables(['-A', chain_name, '-j', 'DROP'])

    def _setup_nftables_rules(
        self,
        sandbox_id: str,
        cgroup_path: Path,
        policy: NetworkPolicy,
    ) -> None:
        """Set up nftables rules for a sandbox."""
        chain_name = f"sandbox_{sandbox_id.replace('-', '_')}"
        cgroup_rel = str(cgroup_path).replace('/sys/fs/cgroup', '')

        # Create table if not exists
        self._run_nft(f'add table inet {self.NFT_TABLE}', ignore_errors=True)

        # Create chain for this sandbox
        self._run_nft(f'''
            add chain inet {self.NFT_TABLE} {chain_name}
        ''')

        # Add jump from output hook
        self._run_nft(f'''
            add chain inet {self.NFT_TABLE} output {{ type filter hook output priority 0; policy accept; }}
            add rule inet {self.NFT_TABLE} output socket cgroupv2 level 2 "{cgroup_rel}" jump {chain_name}
        ''', ignore_errors=True)

        # Build rules
        rules = []

        if policy.deny_all:
            if policy.allow_loopback:
                rules.append('oifname "lo" accept')

            if policy.allow_dns:
                for dns in policy.dns_servers:
                    rules.append(f'ip daddr {dns} udp dport 53 accept')
                    rules.append(f'ip daddr {dns} tcp dport 53 accept')

            rules.append('ct state established,related accept')

            if policy.log_blocked:
                rules.append(f'log prefix "{policy.log_prefix} " drop')
            else:
                rules.append('drop')

        else:
            if policy.allow_loopback:
                rules.append('oifname "lo" accept')

            rules.append('ct state established,related accept')

            if policy.allow_dns:
                for dns in policy.dns_servers:
                    rules.append(f'ip daddr {dns} udp dport 53 accept')

            # Blocked first
            for cidr in policy.blocked_cidrs:
                rules.append(f'ip daddr {cidr} drop')

            for port in policy.blocked_ports:
                rules.append(f'tcp dport {port} drop')
                rules.append(f'udp dport {port} drop')

            # Then allowed
            for cidr in policy.allowed_cidrs:
                rules.append(f'ip daddr {cidr} accept')

            for port in policy.allowed_ports:
                rules.append(f'tcp dport {port} accept')
                if policy.allow_udp:
                    rules.append(f'udp dport {port} accept')

            if policy.allow_icmp:
                rules.append('icmp type echo-request accept')

            if policy.log_blocked:
                rules.append(f'log prefix "{policy.log_prefix} " drop')
            else:
                rules.append('drop')

        # Apply rules
        for rule in rules:
            self._run_nft(f'add rule inet {self.NFT_TABLE} {chain_name} {rule}')

    def cleanup_sandbox_rules(self, sandbox_id: str) -> Tuple[bool, str]:
        """
        Remove firewall rules for a sandbox.

        Args:
            sandbox_id: Sandbox identifier

        Returns:
            (success, message)
        """
        if not self.is_available:
            return True, "Firewall not available"

        with self._lock:
            if sandbox_id not in self._active_sandboxes:
                return True, "No rules to clean up"

            try:
                if self._backend == FirewallBackend.IPTABLES:
                    self._cleanup_iptables_rules(sandbox_id)
                else:
                    self._cleanup_nftables_rules(sandbox_id)

                del self._active_sandboxes[sandbox_id]
                logger.debug(f"Cleaned up firewall rules for {sandbox_id}")
                return True, "Rules cleaned up"

            except Exception as e:
                logger.error(f"Failed to cleanup firewall for {sandbox_id}: {e}")
                return False, str(e)

    def _cleanup_iptables_rules(self, sandbox_id: str) -> None:
        """Clean up iptables rules for a sandbox."""
        chain_name = f"{self.CHAIN_PREFIX}{sandbox_id.replace('-', '_').upper()}"

        # Remove jump rule
        if self._has_cgroup_match:
            cgroup_path = self._active_sandboxes.get(sandbox_id)
            if cgroup_path:
                cgroup_rel = str(cgroup_path).replace('/sys/fs/cgroup', '')
                self._run_iptables([
                    '-D', 'OUTPUT',
                    '-m', 'cgroup', '--path', cgroup_rel,
                    '-j', chain_name,
                ], ignore_errors=True)

        # Flush and delete chain
        self._run_iptables(['-F', chain_name], ignore_errors=True)
        self._run_iptables(['-X', chain_name], ignore_errors=True)

    def _cleanup_nftables_rules(self, sandbox_id: str) -> None:
        """Clean up nftables rules for a sandbox."""
        chain_name = f"sandbox_{sandbox_id.replace('-', '_')}"

        # Delete chain (and its rules)
        self._run_nft(
            f'delete chain inet {self.NFT_TABLE} {chain_name}',
            ignore_errors=True,
        )

    def cleanup_all(self) -> None:
        """Clean up all sandbox firewall rules."""
        with self._lock:
            for sandbox_id in list(self._active_sandboxes.keys()):
                self.cleanup_sandbox_rules(sandbox_id)

            # Clean up nftables table if using nftables
            if self._backend == FirewallBackend.NFTABLES:
                self._run_nft(
                    f'delete table inet {self.NFT_TABLE}',
                    ignore_errors=True,
                )

    def _parse_host_port(self, host_str: str) -> Tuple[str, Optional[int]]:
        """Parse host:port string."""
        if ':' in host_str:
            parts = host_str.rsplit(':', 1)
            try:
                return parts[0], int(parts[1])
            except ValueError:
                return host_str, None
        return host_str, None

    def _run_iptables(
        self,
        args: List[str],
        ignore_errors: bool = False,
    ) -> subprocess.CompletedProcess:
        """Run an iptables command."""
        cmd = ['iptables'] + args
        logger.debug(f"Running: {' '.join(cmd)}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=10,
        )

        if result.returncode != 0 and not ignore_errors:
            error = result.stderr.decode().strip()
            raise RuntimeError(f"iptables failed: {error}")

        return result

    def _run_nft(
        self,
        commands: str,
        ignore_errors: bool = False,
    ) -> subprocess.CompletedProcess:
        """Run nftables commands."""
        commands = ' '.join(commands.split())
        cmd = ['nft', '-f', '-']
        logger.debug(f"Running nft: {commands[:80]}...")

        result = subprocess.run(
            cmd,
            input=commands.encode(),
            capture_output=True,
            timeout=10,
        )

        if result.returncode != 0 and not ignore_errors:
            error = result.stderr.decode().strip()
            raise RuntimeError(f"nftables failed: {error}")

        return result

    def get_sandbox_rules(self, sandbox_id: str) -> str:
        """Get current rules for a sandbox (for debugging)."""
        if not self.is_available:
            return "Firewall not available"

        if sandbox_id not in self._active_sandboxes:
            return "No rules for this sandbox"

        try:
            if self._backend == FirewallBackend.IPTABLES:
                chain_name = f"{self.CHAIN_PREFIX}{sandbox_id.replace('-', '_').upper()}"
                result = subprocess.run(
                    ['iptables', '-L', chain_name, '-n', '-v'],
                    capture_output=True,
                    timeout=5,
                )
                return result.stdout.decode() if result.returncode == 0 else "No rules"
            else:
                chain_name = f"sandbox_{sandbox_id.replace('-', '_')}"
                result = subprocess.run(
                    ['nft', 'list', 'chain', 'inet', self.NFT_TABLE, chain_name],
                    capture_output=True,
                    timeout=5,
                )
                return result.stdout.decode() if result.returncode == 0 else "No rules"
        except Exception as e:
            return f"Error: {e}"


# Global firewall instance
_sandbox_firewall: Optional[SandboxFirewall] = None


def get_sandbox_firewall() -> SandboxFirewall:
    """Get the global sandbox firewall instance."""
    global _sandbox_firewall
    if _sandbox_firewall is None:
        _sandbox_firewall = SandboxFirewall()
    return _sandbox_firewall


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

    print("Testing Sandbox Network Policy...")

    firewall = SandboxFirewall()
    print(f"\nCapabilities: {firewall.get_capabilities()}")

    # Test policy creation
    print("\nPolicy examples:")

    for name, policy in [
        ("deny_all", NetworkPolicy.allow_none()),
        ("loopback_only", NetworkPolicy.loopback_only()),
        ("internal_only", NetworkPolicy.internal_only()),
        ("unrestricted", NetworkPolicy.unrestricted()),
    ]:
        print(f"  {name}:")
        print(f"    deny_all={policy.deny_all}, allow_loopback={policy.allow_loopback}")
        print(f"    allow_dns={policy.allow_dns}, allowed_cidrs={policy.allowed_cidrs}")

    # Test boundary mode policies
    print("\nBoundary mode policies:")
    for mode in range(6):
        policy = NetworkPolicy.for_boundary_mode(mode)
        print(f"  Mode {mode}: deny_all={policy.deny_all}, loopback={policy.allow_loopback}, dns={policy.allow_dns}")

    if firewall.is_available:
        print("\nFirewall is available - could apply rules")
    else:
        print("\nFirewall not available (need root and iptables/nftables)")

    print("\nNetwork policy test complete.")
