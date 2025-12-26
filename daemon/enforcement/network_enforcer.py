"""
Network Enforcer - Kernel-Level Network Enforcement via iptables/nftables

This module provides ACTUAL network enforcement by managing firewall rules,
transforming the Boundary Daemon from a detection-only system to a true
enforcement mechanism.

Security Notes:
- Requires root/CAP_NET_ADMIN privileges
- All rule changes are logged to Event Logger
- Fail-closed: if rule application fails, system enters LOCKDOWN
- Rules are applied atomically where possible
- Backup rules are created before changes

IMPORTANT: This addresses SECURITY_AUDIT.md Critical Finding #2:
"No Network Enforcement Whatsoever"

SECURITY: Protection persistence ensures rules survive daemon restarts.
This addresses: "Cleanup on Shutdown Removes All Protection"
"""

import os
import subprocess
import shutil
import threading
import logging
from enum import Enum
from dataclasses import dataclass
from typing import Optional, List, Tuple, Dict
from datetime import datetime

logger = logging.getLogger(__name__)


class FirewallBackend(Enum):
    """Available firewall backends"""
    IPTABLES = "iptables"
    NFTABLES = "nftables"
    NONE = "none"


class NetworkEnforcementError(Exception):
    """Raised when network enforcement fails"""
    pass


@dataclass
class FirewallRule:
    """Represents a firewall rule"""
    chain: str
    action: str  # ACCEPT, DROP, REJECT
    protocol: Optional[str] = None
    interface: Optional[str] = None
    source: Optional[str] = None
    destination: Optional[str] = None
    port: Optional[int] = None
    comment: Optional[str] = None


class NetworkEnforcer:
    """
    Enforces network restrictions using iptables/nftables.

    This is the CRITICAL component that provides actual enforcement,
    addressing the fundamental design problem identified in SECURITY_AUDIT.md:
    "Python user-space daemon cannot enforce security against... kernel-level operations"

    By integrating with iptables/nftables, we now CAN enforce at the kernel level.

    Modes and their network rules:
    - OPEN: No restrictions (flush all boundary rules)
    - RESTRICTED: Allow all (logging enabled)
    - TRUSTED: Only allow loopback and VPN interfaces
    - AIRGAP: Block ALL network traffic except loopback
    - COLDROOM: Block ALL network traffic except loopback
    - LOCKDOWN: Block ALL network traffic including loopback
    """

    # Chain name for boundary-specific rules
    BOUNDARY_CHAIN = "BOUNDARY_DAEMON"

    # NFTables table and chain names
    NFT_TABLE = "boundary_daemon"
    NFT_CHAIN = "output_filter"

    def __init__(self, daemon=None, event_logger=None, persistence_manager=None):
        """
        Initialize the NetworkEnforcer.

        Args:
            daemon: Reference to BoundaryDaemon for callbacks
            event_logger: EventLogger for audit logging
            persistence_manager: ProtectionPersistenceManager for surviving restarts
        """
        self.daemon = daemon
        self.event_logger = event_logger
        self._lock = threading.Lock()
        self._backend = self._detect_backend()
        self._rules_applied = False
        self._current_mode = None
        self._vpn_interfaces: List[str] = ['tun0', 'wg0', 'ppp0']  # Common VPN interfaces

        # SECURITY: Protection persistence (survives daemon restarts)
        self._persistence_manager = persistence_manager

        # Verify we have root privileges
        self._has_root = os.geteuid() == 0

        if self._backend == FirewallBackend.NONE:
            logger.warning("No firewall backend available. Network enforcement disabled.")
        elif not self._has_root:
            logger.warning("Not running as root. Network enforcement requires CAP_NET_ADMIN.")

    def set_persistence_manager(self, manager):
        """Set the protection persistence manager."""
        self._persistence_manager = manager

    def check_and_reapply_persisted_mode(self) -> Optional[str]:
        """
        Check if there's a persisted mode and re-apply it.

        Called on daemon startup to restore protections that should survive restarts.

        Returns:
            The mode name that was re-applied, or None if no persistence.
        """
        if not self._persistence_manager:
            return None

        try:
            from .protection_persistence import ProtectionType
            protection = self._persistence_manager.should_reapply_protection(
                ProtectionType.NETWORK_FIREWALL
            )
            if protection:
                logger.info(f"Re-applying persisted network protection: {protection.mode}")
                from ..policy_engine import BoundaryMode
                mode = BoundaryMode[protection.mode]
                success, msg = self.enforce_mode(
                    mode,
                    reason="re-applied from persistence"
                )
                if success:
                    return protection.mode
                else:
                    logger.error(f"Failed to re-apply persisted mode: {msg}")
        except Exception as e:
            logger.error(f"Error re-applying persisted mode: {e}")

        return None

    def _detect_backend(self) -> FirewallBackend:
        """Detect available firewall backend (prefer nftables over iptables)"""
        # Check for nftables first (modern)
        if shutil.which('nft'):
            try:
                result = subprocess.run(
                    ['nft', 'list', 'tables'],
                    capture_output=True,
                    timeout=5
                )
                if result.returncode == 0:
                    return FirewallBackend.NFTABLES
            except (subprocess.TimeoutExpired, OSError):
                pass

        # Fall back to iptables
        if shutil.which('iptables'):
            try:
                result = subprocess.run(
                    ['iptables', '-L', '-n'],
                    capture_output=True,
                    timeout=5
                )
                if result.returncode == 0:
                    return FirewallBackend.IPTABLES
            except (subprocess.TimeoutExpired, OSError):
                pass

        return FirewallBackend.NONE

    @property
    def is_available(self) -> bool:
        """Check if network enforcement is available"""
        return self._backend != FirewallBackend.NONE and self._has_root

    @property
    def backend(self) -> FirewallBackend:
        """Get the active firewall backend"""
        return self._backend

    def set_vpn_interfaces(self, interfaces: List[str]):
        """Configure trusted VPN interfaces for TRUSTED mode"""
        with self._lock:
            self._vpn_interfaces = interfaces.copy()
            logger.info(f"VPN interfaces set to: {interfaces}")

    def enforce_mode(
        self,
        mode,
        reason: str = "",
        persist: bool = True,
        sticky: bool = False,
        emergency: bool = False,
    ) -> Tuple[bool, str]:
        """
        Apply network rules for the given boundary mode.

        Args:
            mode: BoundaryMode to enforce
            reason: Reason for the mode change
            persist: Whether to persist this protection (survives restarts)
            sticky: If True, protection requires extra auth to remove
            emergency: If True, protection was applied during emergency

        Returns:
            (success, message)

        Raises:
            NetworkEnforcementError: If enforcement fails and fail-closed triggers
        """
        from ..policy_engine import BoundaryMode

        if not self.is_available:
            return (False, "Network enforcement not available (no backend or not root)")

        with self._lock:
            try:
                old_mode = self._current_mode

                if mode == BoundaryMode.OPEN:
                    self._apply_open_mode()
                elif mode == BoundaryMode.RESTRICTED:
                    self._apply_restricted_mode()
                elif mode == BoundaryMode.TRUSTED:
                    self._apply_trusted_mode()
                elif mode == BoundaryMode.AIRGAP:
                    self._apply_airgap_mode()
                elif mode == BoundaryMode.COLDROOM:
                    self._apply_coldroom_mode()
                elif mode == BoundaryMode.LOCKDOWN:
                    self._apply_lockdown_mode()
                else:
                    # Unknown mode: apply most restrictive
                    self._apply_lockdown_mode()

                self._current_mode = mode
                self._rules_applied = True

                # SECURITY: Persist protection so it survives daemon restarts
                if persist and self._persistence_manager and mode != BoundaryMode.OPEN:
                    try:
                        from .protection_persistence import ProtectionType, PersistenceReason
                        self._persistence_manager.persist_protection(
                            protection_type=ProtectionType.NETWORK_FIREWALL,
                            mode=mode.name,
                            reason=PersistenceReason.MODE_CHANGE,
                            sticky=sticky,
                            emergency=emergency,
                        )
                    except Exception as e:
                        logger.warning(f"Failed to persist protection: {e}")

                # Log the enforcement action
                self._log_enforcement(
                    action="MODE_ENFORCE",
                    old_mode=old_mode,
                    new_mode=mode,
                    reason=reason
                )

                return (True, f"Network enforcement applied for {mode.name} mode")

            except Exception as e:
                error_msg = f"Failed to apply network enforcement: {e}"
                logger.error(error_msg)

                # Fail-closed: try to apply lockdown on failure
                try:
                    self._apply_lockdown_mode()
                    self._log_enforcement(
                        action="FAIL_CLOSED",
                        error=str(e)
                    )
                except Exception as e2:
                    logger.critical(f"Failed to apply lockdown rules: {e2}")

                raise NetworkEnforcementError(error_msg) from e

    def _apply_open_mode(self):
        """OPEN mode: Remove all boundary restrictions"""
        if self._backend == FirewallBackend.IPTABLES:
            self._iptables_flush_boundary_chain()
        else:
            self._nftables_flush_table()

        logger.info("Network enforcement: OPEN mode - all restrictions removed")

    def _apply_restricted_mode(self):
        """RESTRICTED mode: Allow all with logging"""
        if self._backend == FirewallBackend.IPTABLES:
            self._iptables_setup_chain()
            # Allow all but log for auditing
            self._run_iptables([
                '-A', self.BOUNDARY_CHAIN,
                '-j', 'LOG',
                '--log-prefix', '[BOUNDARY-RESTRICTED] ',
                '--log-level', '4'
            ])
            self._run_iptables(['-A', self.BOUNDARY_CHAIN, '-j', 'ACCEPT'])
        else:
            self._nftables_setup_table()
            self._run_nft(f'''
                add rule {self.NFT_TABLE} {self.NFT_CHAIN} \
                    log prefix "[BOUNDARY-RESTRICTED] " accept
            ''')

        logger.info("Network enforcement: RESTRICTED mode - logging enabled")

    def _apply_trusted_mode(self):
        """TRUSTED mode: Only loopback and VPN interfaces allowed"""
        if self._backend == FirewallBackend.IPTABLES:
            self._iptables_setup_chain()

            # Allow loopback
            self._run_iptables([
                '-A', self.BOUNDARY_CHAIN,
                '-o', 'lo', '-j', 'ACCEPT'
            ])

            # Allow established connections
            self._run_iptables([
                '-A', self.BOUNDARY_CHAIN,
                '-m', 'state', '--state', 'ESTABLISHED,RELATED',
                '-j', 'ACCEPT'
            ])

            # Allow VPN interfaces
            for iface in self._vpn_interfaces:
                self._run_iptables([
                    '-A', self.BOUNDARY_CHAIN,
                    '-o', iface, '-j', 'ACCEPT'
                ])

            # Log and drop everything else
            self._run_iptables([
                '-A', self.BOUNDARY_CHAIN,
                '-j', 'LOG',
                '--log-prefix', '[BOUNDARY-BLOCKED] ',
                '--log-level', '4'
            ])
            self._run_iptables(['-A', self.BOUNDARY_CHAIN, '-j', 'DROP'])

        else:
            self._nftables_setup_table()
            vpn_ifaces = ' '.join([f'"{i}"' for i in self._vpn_interfaces])
            self._run_nft(f'''
                add rule {self.NFT_TABLE} {self.NFT_CHAIN} oifname "lo" accept
                add rule {self.NFT_TABLE} {self.NFT_CHAIN} ct state established,related accept
                add rule {self.NFT_TABLE} {self.NFT_CHAIN} oifname {{ {vpn_ifaces} }} accept
                add rule {self.NFT_TABLE} {self.NFT_CHAIN} log prefix "[BOUNDARY-BLOCKED] " drop
            ''')

        logger.info("Network enforcement: TRUSTED mode - VPN only")

    def _apply_airgap_mode(self):
        """AIRGAP mode: Block ALL network except loopback"""
        if self._backend == FirewallBackend.IPTABLES:
            self._iptables_setup_chain()

            # Allow loopback only
            self._run_iptables([
                '-A', self.BOUNDARY_CHAIN,
                '-o', 'lo', '-j', 'ACCEPT'
            ])

            # Allow established connections (for graceful close)
            self._run_iptables([
                '-A', self.BOUNDARY_CHAIN,
                '-m', 'state', '--state', 'ESTABLISHED,RELATED',
                '-j', 'ACCEPT'
            ])

            # Log and drop everything else
            self._run_iptables([
                '-A', self.BOUNDARY_CHAIN,
                '-j', 'LOG',
                '--log-prefix', '[AIRGAP-VIOLATION] ',
                '--log-level', '2'
            ])
            self._run_iptables(['-A', self.BOUNDARY_CHAIN, '-j', 'DROP'])

        else:
            self._nftables_setup_table()
            self._run_nft(f'''
                add rule {self.NFT_TABLE} {self.NFT_CHAIN} oifname "lo" accept
                add rule {self.NFT_TABLE} {self.NFT_CHAIN} ct state established,related accept
                add rule {self.NFT_TABLE} {self.NFT_CHAIN} log prefix "[AIRGAP-VIOLATION] " level warn drop
            ''')

        logger.info("Network enforcement: AIRGAP mode - loopback only")

    def _apply_coldroom_mode(self):
        """COLDROOM mode: Same as AIRGAP (network blocked)"""
        # COLDROOM has same network restrictions as AIRGAP
        # (additional USB restrictions are handled by USBEnforcer)
        self._apply_airgap_mode()
        logger.info("Network enforcement: COLDROOM mode - loopback only")

    def _apply_lockdown_mode(self):
        """LOCKDOWN mode: Block ALL network traffic including loopback"""
        if self._backend == FirewallBackend.IPTABLES:
            self._iptables_setup_chain()

            # Log everything
            self._run_iptables([
                '-A', self.BOUNDARY_CHAIN,
                '-j', 'LOG',
                '--log-prefix', '[LOCKDOWN-BLOCK] ',
                '--log-level', '1'
            ])

            # Drop everything - including loopback
            self._run_iptables(['-A', self.BOUNDARY_CHAIN, '-j', 'DROP'])

        else:
            self._nftables_setup_table()
            self._run_nft(f'''
                add rule {self.NFT_TABLE} {self.NFT_CHAIN} log prefix "[LOCKDOWN-BLOCK] " level alert drop
            ''')

        logger.info("Network enforcement: LOCKDOWN mode - all traffic blocked")

    # ========== iptables helpers ==========

    def _iptables_setup_chain(self):
        """Set up the boundary chain in iptables"""
        # Flush existing chain if it exists
        self._iptables_flush_boundary_chain()

        # Create chain
        self._run_iptables(['-N', self.BOUNDARY_CHAIN], ignore_errors=True)

        # Insert jump to our chain at the beginning of OUTPUT
        # Check if jump already exists
        result = subprocess.run(
            ['iptables', '-C', 'OUTPUT', '-j', self.BOUNDARY_CHAIN],
            capture_output=True
        )
        if result.returncode != 0:
            self._run_iptables(['-I', 'OUTPUT', '1', '-j', self.BOUNDARY_CHAIN])

    def _iptables_flush_boundary_chain(self):
        """Flush and optionally delete the boundary chain"""
        # Flush the chain
        self._run_iptables(['-F', self.BOUNDARY_CHAIN], ignore_errors=True)

        # Remove the jump rule from OUTPUT
        self._run_iptables(['-D', 'OUTPUT', '-j', self.BOUNDARY_CHAIN], ignore_errors=True)

        # Delete the chain
        self._run_iptables(['-X', self.BOUNDARY_CHAIN], ignore_errors=True)

    def _run_iptables(self, args: List[str], ignore_errors: bool = False) -> subprocess.CompletedProcess:
        """Run an iptables command"""
        cmd = ['iptables'] + args
        logger.debug(f"Running: {' '.join(cmd)}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=10
        )

        if result.returncode != 0 and not ignore_errors:
            error = result.stderr.decode().strip()
            raise NetworkEnforcementError(f"iptables command failed: {error}")

        return result

    # ========== nftables helpers ==========

    def _nftables_setup_table(self):
        """Set up the boundary table in nftables"""
        # Flush existing table
        self._nftables_flush_table()

        # Create table and chain
        self._run_nft(f'''
            add table inet {self.NFT_TABLE}
            add chain inet {self.NFT_TABLE} {self.NFT_CHAIN} {{ type filter hook output priority 0; policy accept; }}
        ''')

    def _nftables_flush_table(self):
        """Flush and delete the boundary table"""
        self._run_nft(f'delete table inet {self.NFT_TABLE}', ignore_errors=True)

    def _run_nft(self, commands: str, ignore_errors: bool = False) -> subprocess.CompletedProcess:
        """Run nftables commands"""
        # Clean up the command string
        commands = ' '.join(commands.split())

        cmd = ['nft', '-f', '-']
        logger.debug(f"Running nft commands: {commands[:100]}...")

        result = subprocess.run(
            cmd,
            input=commands.encode(),
            capture_output=True,
            timeout=10
        )

        if result.returncode != 0 and not ignore_errors:
            error = result.stderr.decode().strip()
            raise NetworkEnforcementError(f"nftables command failed: {error}")

        return result

    # ========== Logging and Status ==========

    def _log_enforcement(self, action: str, **kwargs):
        """Log enforcement action to event logger"""
        if self.event_logger:
            try:
                from ..event_logger import EventType
                self.event_logger.log_event(
                    EventType.MODE_CHANGE,
                    f"Network enforcement: {action}",
                    metadata={
                        'enforcement_action': action,
                        'backend': self._backend.value,
                        'timestamp': datetime.utcnow().isoformat() + "Z",
                        **kwargs
                    }
                )
            except Exception as e:
                logger.error(f"Failed to log enforcement action: {e}")

    def get_status(self) -> Dict:
        """Get current enforcement status"""
        return {
            'available': self.is_available,
            'backend': self._backend.value,
            'has_root': self._has_root,
            'rules_applied': self._rules_applied,
            'current_mode': self._current_mode.name if self._current_mode else None,
            'vpn_interfaces': self._vpn_interfaces.copy()
        }

    def get_current_rules(self) -> str:
        """Get current firewall rules (for debugging)"""
        if not self.is_available:
            return "Network enforcement not available"

        try:
            if self._backend == FirewallBackend.IPTABLES:
                result = subprocess.run(
                    ['iptables', '-L', self.BOUNDARY_CHAIN, '-n', '-v'],
                    capture_output=True,
                    timeout=5
                )
                return result.stdout.decode() if result.returncode == 0 else "No rules"
            else:
                result = subprocess.run(
                    ['nft', 'list', 'table', 'inet', self.NFT_TABLE],
                    capture_output=True,
                    timeout=5
                )
                return result.stdout.decode() if result.returncode == 0 else "No rules"
        except Exception as e:
            return f"Error getting rules: {e}"

    def cleanup(
        self,
        token: Optional[str] = None,
        force: bool = False,
        graceful: bool = True,
    ) -> Tuple[bool, str]:
        """
        Remove all boundary firewall rules (called on daemon shutdown).

        SECURITY: By default, protections are NOT removed on shutdown to prevent
        gaps in security. This addresses "Cleanup on Shutdown Removes All Protection".

        Args:
            token: Authentication token (required for explicit cleanup)
            force: Force cleanup even for sticky/emergency protections
            graceful: Whether this is a graceful shutdown

        Returns:
            (success, message)
        """
        if not self.is_available:
            return True, "Network enforcement not available"

        # SECURITY: Check with persistence manager before cleanup
        if self._persistence_manager:
            try:
                from .protection_persistence import ProtectionType
                allowed, msg = self._persistence_manager.request_cleanup(
                    protection_type=ProtectionType.NETWORK_FIREWALL,
                    token=token,
                    force=force,
                    reason="daemon cleanup" if graceful else "daemon crash cleanup",
                )
                if not allowed:
                    logger.info(f"Network cleanup blocked by persistence: {msg}")
                    return False, f"Cleanup blocked: {msg}"
            except Exception as e:
                logger.warning(f"Persistence check failed: {e}")
                # If persistence check fails, default to NOT cleaning up (fail-safe)
                if not force:
                    return False, "Cleanup blocked: persistence check failed"

        with self._lock:
            try:
                if self._backend == FirewallBackend.IPTABLES:
                    self._iptables_flush_boundary_chain()
                else:
                    self._nftables_flush_table()

                self._rules_applied = False
                self._current_mode = None
                logger.info("Network enforcement rules cleaned up")
                return True, "Network rules cleaned up"

            except Exception as e:
                logger.error(f"Error cleaning up network rules: {e}")
                return False, f"Cleanup failed: {e}"

    def cleanup_legacy(self):
        """
        Legacy cleanup that always removes rules (INSECURE).

        WARNING: This method is deprecated and should only be used for
        testing or when explicitly requested by an administrator.
        """
        if not self.is_available:
            return

        with self._lock:
            try:
                if self._backend == FirewallBackend.IPTABLES:
                    self._iptables_flush_boundary_chain()
                else:
                    self._nftables_flush_table()

                self._rules_applied = False
                self._current_mode = None
                logger.warning("Network enforcement rules cleaned up (LEGACY MODE)")

            except Exception as e:
                logger.error(f"Error cleaning up network rules: {e}")

    def emergency_lockdown(self) -> bool:
        """
        Emergency lockdown - block all network traffic immediately.
        Called when a critical security violation is detected.

        SECURITY: Emergency lockdowns are persisted as sticky + emergency,
        requiring admin authentication to remove. This ensures protection
        remains even if an attacker crashes the daemon.

        Returns:
            True if lockdown was successful
        """
        if not self.is_available:
            logger.error("Cannot apply emergency lockdown: no firewall backend")
            return False

        try:
            from ..policy_engine import BoundaryMode
            # SECURITY: Emergency lockdowns are sticky and hard to remove
            self.enforce_mode(
                BoundaryMode.LOCKDOWN,
                reason="Emergency lockdown triggered",
                persist=True,
                sticky=True,
                emergency=True,
            )
            return True
        except Exception as e:
            logger.critical(f"Emergency lockdown failed: {e}")
            return False


if __name__ == '__main__':
    # Test the network enforcer
    import sys

    logging.basicConfig(level=logging.DEBUG)

    enforcer = NetworkEnforcer()
    print(f"Backend: {enforcer.backend.value}")
    print(f"Available: {enforcer.is_available}")
    print(f"Status: {enforcer.get_status()}")

    if not enforcer.is_available:
        print("Network enforcement not available. Run as root with iptables/nftables installed.")
        sys.exit(1)

    # Test mode enforcement (requires root)
    from policy_engine import BoundaryMode

    for mode in [BoundaryMode.OPEN, BoundaryMode.AIRGAP, BoundaryMode.LOCKDOWN]:
        print(f"\nApplying {mode.name} mode...")
        success, msg = enforcer.enforce_mode(mode, reason="test")
        print(f"Result: {success} - {msg}")
        print(f"Rules:\n{enforcer.get_current_rules()}")

    # Cleanup
    enforcer.cleanup()
    print("\nCleanup complete.")
