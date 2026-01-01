"""
Firewall Integration Module

Generates and manages firewall rules (iptables/nftables) based on
daemon policy state. Provides network enforcement to complement
the daemon's detection capabilities.

Supported backends:
- iptables (legacy, widely available)
- nftables (modern, recommended)
- Windows Firewall (via netsh)

Usage:
    from daemon.enforcement.firewall_integration import (
        FirewallManager,
        get_firewall_manager,
    )

    fw = get_firewall_manager()

    # Apply rules for current mode
    fw.apply_mode_rules(BoundaryMode.RESTRICTED)

    # Block specific host
    fw.block_host("malicious.example.com")

    # Generate rules without applying
    rules = fw.generate_rules(BoundaryMode.AIRGAP)

Security Note:
    This module requires root/admin privileges to apply rules.
    It integrates with the daemon's SIEM for audit logging.
"""

import logging
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

IS_WINDOWS = sys.platform == 'win32'
IS_LINUX = sys.platform.startswith('linux')
IS_MACOS = sys.platform == 'darwin'


class FirewallBackend(Enum):
    """Available firewall backends."""
    IPTABLES = "iptables"
    NFTABLES = "nftables"
    WINDOWS = "windows"
    PF = "pf"  # macOS/BSD
    NONE = "none"


class RuleAction(Enum):
    """Firewall rule actions."""
    ACCEPT = "accept"
    DROP = "drop"
    REJECT = "reject"
    LOG = "log"


class RuleDirection(Enum):
    """Traffic direction."""
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    BOTH = "both"


@dataclass
class FirewallRule:
    """A firewall rule definition."""
    name: str
    action: RuleAction
    direction: RuleDirection
    protocol: str = "all"  # tcp, udp, icmp, all
    source: str = ""       # IP, CIDR, or empty for any
    destination: str = ""  # IP, CIDR, or empty for any
    port: Optional[int] = None
    port_range: Optional[Tuple[int, int]] = None
    comment: str = ""
    priority: int = 100    # Lower = higher priority

    def to_iptables(self) -> List[str]:
        """Generate iptables command(s) for this rule."""
        commands = []

        chain = "OUTPUT" if self.direction == RuleDirection.OUTBOUND else "INPUT"
        if self.direction == RuleDirection.BOTH:
            chains = ["INPUT", "OUTPUT"]
        else:
            chains = [chain]

        action_map = {
            RuleAction.ACCEPT: "ACCEPT",
            RuleAction.DROP: "DROP",
            RuleAction.REJECT: "REJECT",
            RuleAction.LOG: "LOG",
        }

        for chain in chains:
            cmd = ["iptables", "-A", chain]

            if self.protocol != "all":
                cmd.extend(["-p", self.protocol])

            if self.source:
                cmd.extend(["-s", self.source])

            if self.destination:
                cmd.extend(["-d", self.destination])

            if self.port and self.protocol in ("tcp", "udp"):
                cmd.extend(["--dport", str(self.port)])

            if self.port_range and self.protocol in ("tcp", "udp"):
                cmd.extend(["--dport", f"{self.port_range[0]}:{self.port_range[1]}"])

            if self.comment:
                cmd.extend(["-m", "comment", "--comment", self.comment[:256]])

            cmd.extend(["-j", action_map[self.action]])

            commands.append(" ".join(cmd))

        return commands

    def to_nftables(self) -> str:
        """Generate nftables rule for this rule."""
        action_map = {
            RuleAction.ACCEPT: "accept",
            RuleAction.DROP: "drop",
            RuleAction.REJECT: "reject",
            RuleAction.LOG: "log",
        }

        parts = []

        if self.protocol != "all":
            parts.append(f"meta l4proto {self.protocol}")

        if self.source:
            parts.append(f"ip saddr {self.source}")

        if self.destination:
            parts.append(f"ip daddr {self.destination}")

        if self.port and self.protocol in ("tcp", "udp"):
            parts.append(f"{self.protocol} dport {self.port}")

        if self.port_range and self.protocol in ("tcp", "udp"):
            parts.append(f"{self.protocol} dport {self.port_range[0]}-{self.port_range[1]}")

        if self.comment:
            parts.append(f'comment "{self.comment[:64]}"')

        parts.append(action_map[self.action])

        return " ".join(parts)


@dataclass
class FirewallConfig:
    """Firewall configuration."""
    # Allowed outbound ports by mode
    open_mode_ports: Set[int] = field(default_factory=lambda: {80, 443, 53, 22})
    restricted_mode_ports: Set[int] = field(default_factory=lambda: {443, 53})
    airgap_mode_ports: Set[int] = field(default_factory=set)  # None allowed

    # Allowed hosts (bypass block rules)
    allowed_hosts: Set[str] = field(default_factory=set)

    # Blocked hosts (always blocked)
    blocked_hosts: Set[str] = field(default_factory=set)

    # Localhost always allowed
    allow_localhost: bool = True

    # Log dropped packets
    log_drops: bool = True

    # Rate limiting
    rate_limit_enabled: bool = True
    rate_limit_per_second: int = 100

    # Chain/table names
    chain_name: str = "BOUNDARY_DAEMON"
    table_name: str = "boundary"


class FirewallManager:
    """
    Manages firewall rules based on daemon policy.

    Provides integration between the daemon's policy decisions
    and actual network enforcement via system firewall.
    """

    def __init__(
        self,
        config: Optional[FirewallConfig] = None,
        event_logger=None,
        siem=None,
    ):
        self.config = config or FirewallConfig()
        self._event_logger = event_logger
        self._siem = siem
        self._backend = self._detect_backend()
        self._applied_rules: List[FirewallRule] = []
        self._is_root = os.geteuid() == 0 if not IS_WINDOWS else self._check_admin()

    def _check_admin(self) -> bool:
        """Check if running as admin on Windows."""
        if not IS_WINDOWS:
            return False
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    def _detect_backend(self) -> FirewallBackend:
        """Detect available firewall backend."""
        if IS_WINDOWS:
            if shutil.which("netsh"):
                return FirewallBackend.WINDOWS
        elif IS_LINUX:
            if shutil.which("nft"):
                return FirewallBackend.NFTABLES
            elif shutil.which("iptables"):
                return FirewallBackend.IPTABLES
        elif IS_MACOS:
            if shutil.which("pfctl"):
                return FirewallBackend.PF

        return FirewallBackend.NONE

    @property
    def backend(self) -> FirewallBackend:
        """Get current firewall backend."""
        return self._backend

    @property
    def is_available(self) -> bool:
        """Check if firewall management is available."""
        return self._backend != FirewallBackend.NONE and self._is_root

    def get_status(self) -> Dict[str, Any]:
        """Get firewall status."""
        return {
            'backend': self._backend.value,
            'available': self.is_available,
            'is_root': self._is_root,
            'applied_rules_count': len(self._applied_rules),
            'config': {
                'chain_name': self.config.chain_name,
                'log_drops': self.config.log_drops,
                'rate_limit_enabled': self.config.rate_limit_enabled,
            }
        }

    def generate_mode_rules(self, mode: str) -> List[FirewallRule]:
        """
        Generate firewall rules for a boundary mode.

        Args:
            mode: Boundary mode (OPEN, RESTRICTED, AIRGAP, etc.)

        Returns:
            List of FirewallRule objects
        """
        rules = []
        mode_upper = mode.upper()

        # Always allow localhost
        if self.config.allow_localhost:
            rules.append(FirewallRule(
                name="allow_localhost",
                action=RuleAction.ACCEPT,
                direction=RuleDirection.BOTH,
                source="127.0.0.0/8",
                destination="127.0.0.0/8",
                comment="Allow localhost",
                priority=10,
            ))

        # Always allow established connections
        rules.append(FirewallRule(
            name="allow_established",
            action=RuleAction.ACCEPT,
            direction=RuleDirection.BOTH,
            comment="Allow established connections",
            priority=20,
        ))

        # Allowed hosts bypass
        for host in self.config.allowed_hosts:
            rules.append(FirewallRule(
                name=f"allow_host_{host}",
                action=RuleAction.ACCEPT,
                direction=RuleDirection.OUTBOUND,
                destination=host,
                comment=f"Allowed host: {host}",
                priority=30,
            ))

        # Blocked hosts (always blocked)
        for host in self.config.blocked_hosts:
            rules.append(FirewallRule(
                name=f"block_host_{host}",
                action=RuleAction.DROP,
                direction=RuleDirection.OUTBOUND,
                destination=host,
                comment=f"Blocked host: {host}",
                priority=25,
            ))

        # Mode-specific rules
        if mode_upper == "AIRGAP":
            # Block ALL outbound except localhost
            rules.append(FirewallRule(
                name="airgap_block_all",
                action=RuleAction.DROP,
                direction=RuleDirection.OUTBOUND,
                comment="AIRGAP: Block all outbound",
                priority=100,
            ))

        elif mode_upper == "COLDROOM":
            # Block all outbound, no exceptions
            rules.append(FirewallRule(
                name="coldroom_block_all",
                action=RuleAction.DROP,
                direction=RuleDirection.BOTH,
                comment="COLDROOM: Block all network",
                priority=100,
            ))

        elif mode_upper == "RESTRICTED":
            # Allow only specific ports
            for port in self.config.restricted_mode_ports:
                rules.append(FirewallRule(
                    name=f"restricted_allow_port_{port}",
                    action=RuleAction.ACCEPT,
                    direction=RuleDirection.OUTBOUND,
                    protocol="tcp",
                    port=port,
                    comment=f"RESTRICTED: Allow port {port}",
                    priority=50,
                ))

            # Block everything else
            rules.append(FirewallRule(
                name="restricted_block_other",
                action=RuleAction.DROP,
                direction=RuleDirection.OUTBOUND,
                comment="RESTRICTED: Block other outbound",
                priority=100,
            ))

        elif mode_upper == "OPEN":
            # Allow configured ports
            for port in self.config.open_mode_ports:
                rules.append(FirewallRule(
                    name=f"open_allow_port_{port}",
                    action=RuleAction.ACCEPT,
                    direction=RuleDirection.OUTBOUND,
                    protocol="tcp",
                    port=port,
                    comment=f"OPEN: Allow port {port}",
                    priority=50,
                ))

            # Allow DNS
            rules.append(FirewallRule(
                name="open_allow_dns",
                action=RuleAction.ACCEPT,
                direction=RuleDirection.OUTBOUND,
                protocol="udp",
                port=53,
                comment="OPEN: Allow DNS",
                priority=50,
            ))

        # Log drops if enabled
        if self.config.log_drops:
            rules.append(FirewallRule(
                name="log_drops",
                action=RuleAction.LOG,
                direction=RuleDirection.BOTH,
                comment="Log dropped packets",
                priority=99,
            ))

        # Sort by priority
        rules.sort(key=lambda r: r.priority)

        return rules

    def generate_iptables_script(self, mode: str) -> str:
        """Generate a complete iptables script for a mode."""
        rules = self.generate_mode_rules(mode)
        chain = self.config.chain_name

        lines = [
            "#!/bin/bash",
            "# Generated by Boundary Daemon",
            f"# Mode: {mode}",
            "",
            "set -e",
            "",
            "# Flush existing chain",
            f"iptables -F {chain} 2>/dev/null || true",
            f"iptables -X {chain} 2>/dev/null || true",
            "",
            "# Create chain",
            f"iptables -N {chain}",
            "",
            "# Add rules",
        ]

        for rule in rules:
            for cmd in rule.to_iptables():
                # Replace chain name
                cmd = cmd.replace("-A INPUT", f"-A {chain}")
                cmd = cmd.replace("-A OUTPUT", f"-A {chain}")
                lines.append(cmd)

        lines.extend([
            "",
            "# Jump to chain from main chains",
            f"iptables -I INPUT -j {chain}",
            f"iptables -I OUTPUT -j {chain}",
            "",
            f'echo "Firewall rules applied for mode: {mode}"',
        ])

        return "\n".join(lines)

    def generate_nftables_config(self, mode: str) -> str:
        """Generate nftables configuration for a mode."""
        rules = self.generate_mode_rules(mode)
        table = self.config.table_name
        chain = self.config.chain_name

        lines = [
            "#!/usr/sbin/nft -f",
            "# Generated by Boundary Daemon",
            f"# Mode: {mode}",
            "",
            f"table inet {table} {{",
            f"    chain {chain}_input {{",
            "        type filter hook input priority 0; policy accept;",
        ]

        for rule in rules:
            if rule.direction in (RuleDirection.INBOUND, RuleDirection.BOTH):
                lines.append(f"        {rule.to_nftables()}")

        lines.extend([
            "    }",
            "",
            f"    chain {chain}_output {{",
            "        type filter hook output priority 0; policy accept;",
        ])

        for rule in rules:
            if rule.direction in (RuleDirection.OUTBOUND, RuleDirection.BOTH):
                lines.append(f"        {rule.to_nftables()}")

        lines.extend([
            "    }",
            "}",
        ])

        return "\n".join(lines)

    def apply_rules(self, rules: List[FirewallRule]) -> Tuple[bool, str]:
        """
        Apply firewall rules.

        Requires root privileges.

        Returns:
            (success, message)
        """
        if not self.is_available:
            return False, f"Firewall not available (backend={self._backend.value}, root={self._is_root})"

        try:
            if self._backend == FirewallBackend.IPTABLES:
                return self._apply_iptables(rules)
            elif self._backend == FirewallBackend.NFTABLES:
                return self._apply_nftables(rules)
            elif self._backend == FirewallBackend.WINDOWS:
                return self._apply_windows(rules)
            else:
                return False, f"Unsupported backend: {self._backend.value}"

        except Exception as e:
            logger.error(f"Failed to apply firewall rules: {e}")
            return False, str(e)

    def _apply_iptables(self, rules: List[FirewallRule]) -> Tuple[bool, str]:
        """Apply rules using iptables."""
        chain = self.config.chain_name

        # Flush existing chain
        subprocess.run(["iptables", "-F", chain], capture_output=True)
        subprocess.run(["iptables", "-X", chain], capture_output=True)

        # Create chain
        result = subprocess.run(["iptables", "-N", chain], capture_output=True)
        if result.returncode != 0:
            return False, f"Failed to create chain: {result.stderr.decode()}"

        # Add rules
        for rule in rules:
            for cmd in rule.to_iptables():
                cmd = cmd.replace("-A INPUT", f"-A {chain}")
                cmd = cmd.replace("-A OUTPUT", f"-A {chain}")
                result = subprocess.run(cmd.split(), capture_output=True)
                if result.returncode != 0:
                    logger.warning(f"Rule failed: {cmd}: {result.stderr.decode()}")

        # Jump to chain
        subprocess.run(["iptables", "-I", "INPUT", "-j", chain], capture_output=True)
        subprocess.run(["iptables", "-I", "OUTPUT", "-j", chain], capture_output=True)

        self._applied_rules = rules
        self._log_event("firewall_rules_applied", {"count": len(rules), "backend": "iptables"})

        return True, f"Applied {len(rules)} iptables rules"

    def _apply_nftables(self, rules: List[FirewallRule]) -> Tuple[bool, str]:
        """Apply rules using nftables."""
        table = self.config.table_name

        # Delete existing table
        subprocess.run(["nft", "delete", "table", "inet", table], capture_output=True)

        # Generate and apply config
        config = self.generate_nftables_config("CUSTOM")

        result = subprocess.run(
            ["nft", "-f", "-"],
            input=config.encode(),
            capture_output=True,
        )

        if result.returncode != 0:
            return False, f"Failed to apply nftables: {result.stderr.decode()}"

        self._applied_rules = rules
        self._log_event("firewall_rules_applied", {"count": len(rules), "backend": "nftables"})

        return True, f"Applied {len(rules)} nftables rules"

    def _apply_windows(self, rules: List[FirewallRule]) -> Tuple[bool, str]:
        """Apply rules using Windows Firewall."""
        # Windows uses netsh advfirewall
        applied = 0

        for rule in rules:
            direction = "in" if rule.direction == RuleDirection.INBOUND else "out"
            action = "allow" if rule.action == RuleAction.ACCEPT else "block"

            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=BoundaryDaemon_{rule.name}",
                f"dir={direction}",
                f"action={action}",
            ]

            if rule.protocol != "all":
                cmd.append(f"protocol={rule.protocol}")

            if rule.destination:
                cmd.append(f"remoteip={rule.destination}")

            if rule.port:
                cmd.append(f"remoteport={rule.port}")

            result = subprocess.run(cmd, capture_output=True)
            if result.returncode == 0:
                applied += 1

        self._applied_rules = rules
        self._log_event("firewall_rules_applied", {"count": applied, "backend": "windows"})

        return True, f"Applied {applied} Windows Firewall rules"

    def clear_rules(self) -> Tuple[bool, str]:
        """Clear all daemon-managed firewall rules."""
        if not self.is_available:
            return False, "Firewall not available"

        try:
            if self._backend == FirewallBackend.IPTABLES:
                chain = self.config.chain_name
                subprocess.run(["iptables", "-D", "INPUT", "-j", chain], capture_output=True)
                subprocess.run(["iptables", "-D", "OUTPUT", "-j", chain], capture_output=True)
                subprocess.run(["iptables", "-F", chain], capture_output=True)
                subprocess.run(["iptables", "-X", chain], capture_output=True)

            elif self._backend == FirewallBackend.NFTABLES:
                table = self.config.table_name
                subprocess.run(["nft", "delete", "table", "inet", table], capture_output=True)

            elif self._backend == FirewallBackend.WINDOWS:
                # Delete rules with our prefix
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    "name=BoundaryDaemon_*"
                ], capture_output=True)

            self._applied_rules = []
            self._log_event("firewall_rules_cleared", {})

            return True, "Firewall rules cleared"

        except Exception as e:
            return False, str(e)

    def block_host(self, host: str) -> Tuple[bool, str]:
        """Block a specific host."""
        self.config.blocked_hosts.add(host)

        rule = FirewallRule(
            name=f"block_{host}",
            action=RuleAction.DROP,
            direction=RuleDirection.OUTBOUND,
            destination=host,
            comment=f"Blocked by daemon: {host}",
            priority=25,
        )

        return self.apply_rules([rule])

    def allow_host(self, host: str) -> Tuple[bool, str]:
        """Allow a specific host."""
        self.config.allowed_hosts.add(host)
        self.config.blocked_hosts.discard(host)

        rule = FirewallRule(
            name=f"allow_{host}",
            action=RuleAction.ACCEPT,
            direction=RuleDirection.OUTBOUND,
            destination=host,
            comment=f"Allowed by daemon: {host}",
            priority=30,
        )

        return self.apply_rules([rule])

    def _log_event(self, event_type: str, data: Dict[str, Any]):
        """Log firewall event to event logger and SIEM."""
        if self._event_logger:
            try:
                from daemon.event_logger import EventType
                self._event_logger.log_event(
                    event_type=EventType.NETWORK_ACTIVITY,
                    data={
                        'firewall_event': event_type,
                        **data,
                    }
                )
            except Exception:
                pass

        if self._siem:
            try:
                self._siem.log_config_change(
                    config_type="firewall",
                    details={
                        'event': event_type,
                        **data,
                    }
                )
            except Exception:
                pass


# Global instance
_firewall_manager: Optional[FirewallManager] = None


def get_firewall_manager(
    config: Optional[FirewallConfig] = None,
    event_logger=None,
    siem=None,
) -> FirewallManager:
    """Get or create the global firewall manager."""
    global _firewall_manager
    if _firewall_manager is None:
        _firewall_manager = FirewallManager(config, event_logger, siem)
    return _firewall_manager


__all__ = [
    'FirewallManager',
    'FirewallConfig',
    'FirewallRule',
    'FirewallBackend',
    'RuleAction',
    'RuleDirection',
    'get_firewall_manager',
]
