"""
eBPF Policy Integration for Boundary Daemon

Integrates eBPF observations with daemon policy engine:
- Provides real-time event feed for policy decisions
- Maps kernel events to policy-relevant information
- Enables observation-based policy enforcement

Note: This is READ-ONLY observation. The daemon makes policy
decisions but does not use eBPF to block operations.
"""

import logging
import queue
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Callable

from .ebpf_observer import (
    eBPFObserver,
    ObservationEvent,
    FileEvent,
    NetworkEvent,
)

logger = logging.getLogger(__name__)


class PolicyAction(Enum):
    """Policy actions based on observations."""
    ALLOW = "allow"
    DENY = "deny"  # Advisory - we can't actually block
    ALERT = "alert"
    LOG = "log"
    IGNORE = "ignore"


@dataclass
class PolicyMatch:
    """A policy match from observation."""
    observation: ObservationEvent
    policy_name: str
    action: PolicyAction
    reason: str = ""
    matched_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ObservationBasedPolicy:
    """A policy rule based on observations."""
    name: str
    description: str = ""
    enabled: bool = True

    # Matching criteria
    event_types: List[str] = field(default_factory=list)  # process, file, network
    match_conditions: Dict[str, Any] = field(default_factory=dict)

    # Action
    action: PolicyAction = PolicyAction.LOG
    severity: str = "info"

    # Rate limiting
    max_matches_per_minute: int = 100
    _match_count: int = 0
    _last_reset: datetime = field(default_factory=datetime.utcnow)


class RealTimeEnforcement:
    """
    Real-time enforcement modes using eBPF observations.

    Note: "Enforcement" here means alerting and logging.
    We cannot actually block operations from user-space.
    """

    class Mode(Enum):
        DISABLED = "disabled"
        MONITOR = "monitor"  # Log only
        ALERT = "alert"  # Log and alert
        STRICT = "strict"  # Log, alert, and recommend actions

    def __init__(self, mode: Optional['RealTimeEnforcement.Mode'] = None):
        self.mode = mode or self.Mode.MONITOR
        self._alert_callbacks: Dict[int, Callable[[PolicyMatch], None]] = {}
        self._next_callback_id = 0
        self._callback_lock = threading.Lock()

    def add_alert_callback(
        self,
        callback: Callable[[PolicyMatch], None],
    ) -> int:
        """Add callback for alerts.

        Returns:
            Callback ID that can be used to remove the callback
        """
        with self._callback_lock:
            callback_id = self._next_callback_id
            self._next_callback_id += 1
            self._alert_callbacks[callback_id] = callback
            return callback_id

    def remove_alert_callback(self, callback_id: int) -> bool:
        """Remove a previously added alert callback.

        Args:
            callback_id: The ID returned from add_alert_callback

        Returns:
            True if callback was found and removed, False otherwise
        """
        with self._callback_lock:
            if callback_id in self._alert_callbacks:
                del self._alert_callbacks[callback_id]
                return True
            return False

    def cleanup(self):
        """Cleanup resources and clear callbacks."""
        with self._callback_lock:
            self._alert_callbacks.clear()

    def process_match(self, match: PolicyMatch) -> None:
        """Process a policy match."""
        if self.mode == self.Mode.DISABLED:
            return

        if self.mode in (self.Mode.ALERT, self.Mode.STRICT):
            with self._callback_lock:
                callbacks = list(self._alert_callbacks.values())
            for callback in callbacks:
                try:
                    callback(match)
                except Exception as e:
                    logger.error(f"Alert callback failed: {e}")


class eBPFPolicyProvider:
    """
    Provides policy decisions based on eBPF observations.

    Integrates with the daemon's policy engine to provide
    real-time visibility into system activity.

    Usage:
        provider = eBPFPolicyProvider()

        # Add policies
        provider.add_policy(ObservationBasedPolicy(
            name="sensitive_file_access",
            event_types=["file"],
            match_conditions={"path": "/etc/shadow"},
            action=PolicyAction.ALERT,
        ))

        # Start observation
        provider.start()

        # In event loop
        matches = provider.get_policy_matches()
        for match in matches:
            print(f"Policy {match.policy_name}: {match.action.value}")

        provider.stop()
    """

    def __init__(
        self,
        observer: Optional[eBPFObserver] = None,
        enforcement: Optional[RealTimeEnforcement] = None,
    ):
        self._observer = observer or eBPFObserver()
        self._enforcement = enforcement or RealTimeEnforcement()

        self._policies: Dict[str, ObservationBasedPolicy] = {}
        self._match_queue: queue.Queue = queue.Queue(maxsize=10000)

        self._running = False
        self._process_thread: Optional[threading.Thread] = None

        # Stats
        self._observations_processed = 0
        self._policies_matched = 0

        # Add default policies
        self._add_default_policies()

    def _add_default_policies(self) -> None:
        """Add default security policies."""
        defaults = [
            ObservationBasedPolicy(
                name="shell_execution",
                description="Detect shell interpreter execution",
                event_types=["process"],
                match_conditions={
                    "comm": ["bash", "sh", "zsh", "dash", "ksh", "csh"],
                },
                action=PolicyAction.LOG,
                severity="info",
            ),
            ObservationBasedPolicy(
                name="network_tool",
                description="Detect network tool execution",
                event_types=["process"],
                match_conditions={
                    "comm": ["curl", "wget", "nc", "netcat", "nmap", "ssh"],
                },
                action=PolicyAction.ALERT,
                severity="medium",
            ),
            ObservationBasedPolicy(
                name="sensitive_file_access",
                description="Detect access to sensitive files",
                event_types=["file"],
                match_conditions={
                    "path_contains": ["/etc/shadow", "/etc/passwd", ".ssh/"],
                },
                action=PolicyAction.ALERT,
                severity="high",
            ),
            ObservationBasedPolicy(
                name="external_connection",
                description="Detect external network connections",
                event_types=["network"],
                match_conditions={
                    "external": True,
                },
                action=PolicyAction.LOG,
                severity="info",
            ),
        ]

        for policy in defaults:
            self.add_policy(policy)

    def add_policy(self, policy: ObservationBasedPolicy) -> None:
        """Add a policy."""
        self._policies[policy.name] = policy
        logger.debug(f"Added policy: {policy.name}")

    def remove_policy(self, name: str) -> bool:
        """Remove a policy."""
        return self._policies.pop(name, None) is not None

    def start(self) -> bool:
        """Start observation and policy matching."""
        if self._running:
            return True

        # Register callback
        self._observer.add_callback(self._process_observation)

        # Start observer
        if not self._observer.start():
            logger.error("Failed to start observer")
            return False

        self._running = True
        logger.info("eBPF policy provider started")
        return True

    def stop(self) -> None:
        """Stop observation."""
        self._running = False
        self._observer.stop()
        logger.info("eBPF policy provider stopped")

    def _process_observation(self, event: ObservationEvent) -> None:
        """Process an observation event."""
        self._observations_processed += 1

        for policy in self._policies.values():
            if not policy.enabled:
                continue

            # Check rate limit
            now = datetime.utcnow()
            if (now - policy._last_reset) > timedelta(minutes=1):
                policy._match_count = 0
                policy._last_reset = now

            if policy._match_count >= policy.max_matches_per_minute:
                continue

            # Check event type
            if policy.event_types and event.event_type not in policy.event_types:
                continue

            # Check conditions
            if self._matches_conditions(event, policy.match_conditions):
                match = PolicyMatch(
                    observation=event,
                    policy_name=policy.name,
                    action=policy.action,
                    reason=f"Matched {policy.description}",
                )

                policy._match_count += 1
                self._policies_matched += 1

                try:
                    self._match_queue.put_nowait(match)
                except queue.Full:
                    pass

                # Process enforcement
                self._enforcement.process_match(match)

    def _matches_conditions(
        self,
        event: ObservationEvent,
        conditions: Dict[str, Any],
    ) -> bool:
        """Check if event matches conditions."""
        if not conditions:
            return True

        for field, expected in conditions.items():
            # Handle special conditions
            if field == "path_contains" and isinstance(event, FileEvent):
                if isinstance(expected, list):
                    if not any(p in event.path for p in expected):
                        return False
                elif expected not in event.path:
                    return False
                continue

            if field == "external" and isinstance(event, NetworkEvent):
                # Check if connection is external (not loopback/private)
                addr = event.dst_addr
                is_external = not (
                    addr.startswith("127.") or
                    addr.startswith("10.") or
                    addr.startswith("192.168.") or
                    addr.startswith("172.16.") or
                    addr == "::1" or
                    addr == ""
                )
                if expected and not is_external:
                    return False
                continue

            # Get event attribute
            event_value = getattr(event, field, None)
            if event_value is None:
                return False

            # Check match
            if isinstance(expected, list):
                if event_value not in expected:
                    return False
            elif event_value != expected:
                return False

        return True

    def get_policy_matches(self, timeout: float = 0.1) -> List[PolicyMatch]:
        """Get pending policy matches."""
        matches = []
        deadline = datetime.utcnow().timestamp() + timeout

        while datetime.utcnow().timestamp() < deadline:
            try:
                match = self._match_queue.get(timeout=0.01)
                matches.append(match)
            except queue.Empty:
                break

        return matches

    def get_stats(self) -> Dict[str, Any]:
        """Get provider statistics."""
        return {
            'observer': self._observer.get_stats(),
            'policies_loaded': len(self._policies),
            'observations_processed': self._observations_processed,
            'policies_matched': self._policies_matched,
            'enforcement_mode': self._enforcement.mode.value,
        }

    def export_policy_report(self) -> Dict[str, Any]:
        """Export policy configuration and stats."""
        return {
            'policies': [
                {
                    'name': p.name,
                    'description': p.description,
                    'enabled': p.enabled,
                    'action': p.action.value,
                    'severity': p.severity,
                    'match_count': p._match_count,
                }
                for p in self._policies.values()
            ],
            'stats': self.get_stats(),
        }


if __name__ == '__main__':
    import time

    print("Testing eBPF Policy Integration...")

    provider = eBPFPolicyProvider()

    # Add custom policy
    provider.add_policy(ObservationBasedPolicy(
        name="python_execution",
        description="Detect Python interpreter",
        event_types=["process"],
        match_conditions={"comm": ["python", "python3"]},
        action=PolicyAction.LOG,
    ))

    print(f"\nPolicies loaded: {len(provider._policies)}")
    for name, policy in provider._policies.items():
        print(f"  - {name}: {policy.action.value}")

    if provider.start():
        print("\nProvider started, watching for 5 seconds...")

        end_time = time.time() + 5
        while time.time() < end_time:
            matches = provider.get_policy_matches(timeout=0.5)
            for match in matches:
                print(f"  MATCH: {match.policy_name} - {match.action.value}")
                if hasattr(match.observation, 'comm'):
                    print(f"    Process: {match.observation.comm}")
            time.sleep(0.1)

        print(f"\nStats: {provider.get_stats()}")
        provider.stop()
    else:
        print("\nProvider could not start (may need root or BCC)")
        print("Module loaded successfully for integration")

    print("\nPolicy integration test complete.")
