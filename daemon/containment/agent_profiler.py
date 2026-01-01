"""
Autonomous Agent Containment Protocol - Industry-first AI agent containment.

Phase 3 Cutting-Edge Innovation: Standardized protocol for detecting and
containing runaway AI agents with graduated response levels.

Key Concepts:
- Agent Profiling: Establish behavioral baselines
- Anomaly Detection: Identify deviations from normal patterns
- Graduated Response: WARN → THROTTLE → ISOLATE → SUSPEND → TERMINATE
- Recovery Protocol: Human-reviewed release from containment

Architecture:
    ┌─────────────────────────────────────────────────────────────────┐
    │                 AGENT CONTAINMENT PROTOCOL                      │
    ├─────────────────────────────────────────────────────────────────┤
    │                                                                 │
    │  AGENT ACTIVITY                 BEHAVIOR BASELINE              │
    │  ┌────────────────┐            ┌────────────────┐              │
    │  │ Tool calls     │            │ Avg tools/min  │              │
    │  │ Resource use   │───────────►│ Avg memory MB  │              │
    │  │ Output patterns│            │ Normal outputs │              │
    │  │ API requests   │            │ API patterns   │              │
    │  └────────────────┘            └───────┬────────┘              │
    │                                        │                        │
    │                                        ▼                        │
    │                               ┌────────────────┐               │
    │                               │ ANOMALY ENGINE │               │
    │                               │                │               │
    │                               │ • Frequency    │               │
    │                               │ • Resource     │               │
    │                               │ • Capability   │               │
    │                               │ • Output       │               │
    │                               └───────┬────────┘               │
    │                                       │                         │
    │                    ┌──────────────────┼──────────────────┐     │
    │                    ▼                  ▼                  ▼     │
    │              ┌─────────┐        ┌─────────┐        ┌─────────┐│
    │              │  WARN   │───────►│THROTTLE │───────►│ ISOLATE ││
    │              │         │        │         │        │         ││
    │              │Log+Alert│        │Rate-limit│       │Sandbox  ││
    │              └─────────┘        └─────────┘        └────┬────┘│
    │                                                         │     │
    │                                      ┌──────────────────┘     │
    │                                      ▼                        │
    │                               ┌─────────────┐                 │
    │                               │   SUSPEND   │                 │
    │                               │             │                 │
    │                               │ Pause agent │                 │
    │                               │ Await human │                 │
    │                               └──────┬──────┘                 │
    │                                      │                        │
    │                                      ▼                        │
    │                               ┌─────────────┐                 │
    │                               │  TERMINATE  │                 │
    │                               │             │                 │
    │                               │ Kill process│                 │
    │                               │ Preserve    │                 │
    │                               │ forensics   │                 │
    │                               └─────────────┘                 │
    └─────────────────────────────────────────────────────────────────┘

Anomaly Types:
- FREQUENCY: Sudden spike in tool call rate
- RESOURCE: Memory/CPU exceeds thresholds
- CAPABILITY: Attempts to access outside capability set
- OUTPUT: Patterns matching known attack signatures
- DURATION: Running longer than expected
- ESCALATION: Progressive boundary testing
"""

import json
import logging
import os
import signal
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Any, Callable, Deque
import hashlib

logger = logging.getLogger(__name__)


class AnomalyType(Enum):
    """Types of behavioral anomalies."""
    FREQUENCY = "frequency"         # Tool call rate spike
    RESOURCE = "resource"           # Memory/CPU spike
    CAPABILITY = "capability"       # Out-of-bounds access attempt
    OUTPUT = "output"               # Suspicious output pattern
    DURATION = "duration"           # Running too long
    ESCALATION = "escalation"       # Progressive boundary testing
    NETWORK = "network"             # Unusual network activity
    FILESYSTEM = "filesystem"       # Unusual file access


class ContainmentLevel(Enum):
    """Containment levels with increasing severity."""
    NORMAL = 0      # No containment, normal operation
    WARN = 1        # Log and alert, continue execution
    THROTTLE = 2    # Rate-limit tool calls
    ISOLATE = 3     # Move to more restrictive sandbox
    SUSPEND = 4     # Pause agent, await human review
    TERMINATE = 5   # Kill agent process immediately


@dataclass
class BehaviorBaseline:
    """Behavioral baseline for an agent."""
    agent_id: str
    established_at: datetime
    samples: int = 0

    # Tool usage baseline
    avg_tools_per_minute: float = 0.0
    max_tools_per_minute: float = 0.0
    common_tools: Set[str] = field(default_factory=set)
    tool_sequences: List[Tuple[str, str]] = field(default_factory=list)

    # Resource baseline
    avg_memory_mb: float = 0.0
    max_memory_mb: float = 0.0
    avg_cpu_percent: float = 0.0
    max_cpu_percent: float = 0.0

    # Output baseline
    avg_output_length: float = 0.0
    max_output_length: float = 0.0
    output_pattern_hashes: Set[str] = field(default_factory=set)

    # Timing baseline
    avg_session_duration_seconds: float = 0.0
    max_session_duration_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'agent_id': self.agent_id,
            'established_at': self.established_at.isoformat(),
            'samples': self.samples,
            'avg_tools_per_minute': self.avg_tools_per_minute,
            'max_tools_per_minute': self.max_tools_per_minute,
            'common_tools': list(self.common_tools),
            'avg_memory_mb': self.avg_memory_mb,
            'max_memory_mb': self.max_memory_mb,
            'avg_cpu_percent': self.avg_cpu_percent,
            'max_cpu_percent': self.max_cpu_percent,
            'avg_output_length': self.avg_output_length,
            'max_output_length': self.max_output_length,
            'avg_session_duration_seconds': self.avg_session_duration_seconds,
            'max_session_duration_seconds': self.max_session_duration_seconds,
        }


@dataclass
class AgentProfile:
    """Profile of an active agent."""
    agent_id: str
    process_id: Optional[int]
    started_at: datetime
    containment_level: ContainmentLevel = ContainmentLevel.NORMAL
    baseline: Optional[BehaviorBaseline] = None

    # Current metrics
    tool_calls_this_minute: int = 0
    total_tool_calls: int = 0
    current_memory_mb: float = 0.0
    current_cpu_percent: float = 0.0
    last_output_length: int = 0

    # Anomaly tracking
    anomalies: List[Dict[str, Any]] = field(default_factory=list)
    escalation_count: int = 0
    last_escalation: Optional[datetime] = None

    # Containment state
    throttle_delay_ms: int = 0
    isolated_sandbox_id: Optional[str] = None
    suspended_at: Optional[datetime] = None
    terminated_at: Optional[datetime] = None
    preserved_state_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'agent_id': self.agent_id,
            'process_id': self.process_id,
            'started_at': self.started_at.isoformat(),
            'containment_level': self.containment_level.name,
            'tool_calls_this_minute': self.tool_calls_this_minute,
            'total_tool_calls': self.total_tool_calls,
            'current_memory_mb': self.current_memory_mb,
            'current_cpu_percent': self.current_cpu_percent,
            'anomalies': self.anomalies[-10:],  # Last 10
            'escalation_count': self.escalation_count,
        }


@dataclass
class ContainmentAction:
    """A containment action taken against an agent."""
    action_id: str
    agent_id: str
    previous_level: ContainmentLevel
    new_level: ContainmentLevel
    reason: str
    anomaly_type: AnomalyType
    timestamp: datetime
    auto_triggered: bool = True
    human_approved: bool = False
    reversed: bool = False
    reversed_at: Optional[datetime] = None
    reversed_by: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'action_id': self.action_id,
            'agent_id': self.agent_id,
            'previous_level': self.previous_level.name,
            'new_level': self.new_level.name,
            'reason': self.reason,
            'anomaly_type': self.anomaly_type.value,
            'timestamp': self.timestamp.isoformat(),
            'auto_triggered': self.auto_triggered,
            'human_approved': self.human_approved,
            'reversed': self.reversed,
        }


class ContainmentProtocol:
    """
    The Containment Protocol - graduated response to agent anomalies.

    Implements the WARN → THROTTLE → ISOLATE → SUSPEND → TERMINATE
    escalation ladder with human override capability.
    """

    # Default thresholds
    DEFAULT_THRESHOLDS = {
        'tool_rate_warn': 3.0,        # 3x baseline
        'tool_rate_throttle': 5.0,    # 5x baseline
        'tool_rate_isolate': 10.0,    # 10x baseline
        'memory_warn': 1.5,           # 1.5x baseline
        'memory_isolate': 2.0,        # 2x baseline
        'memory_terminate': 3.0,      # 3x baseline
        'cpu_warn': 1.5,
        'cpu_isolate': 2.0,
        'duration_warn': 2.0,         # 2x avg duration
        'duration_suspend': 5.0,      # 5x avg duration
        'escalation_count_suspend': 3,  # 3 escalations
        'escalation_count_terminate': 5,
    }

    def __init__(
        self,
        thresholds: Optional[Dict[str, float]] = None,
        sandbox_manager: Optional[Any] = None,
        auto_escalate: bool = True,
        require_human_for_terminate: bool = True,
        forensics_path: str = "/var/lib/boundary-daemon/forensics",
    ):
        """
        Initialize the Containment Protocol.

        Args:
            thresholds: Custom thresholds (merged with defaults)
            sandbox_manager: Sandbox manager for isolation
            auto_escalate: Whether to auto-escalate on anomalies
            require_human_for_terminate: Require human approval for terminate
            forensics_path: Path for preserving terminated agent state
        """
        self.thresholds = {**self.DEFAULT_THRESHOLDS, **(thresholds or {})}
        self.sandbox_manager = sandbox_manager
        self.auto_escalate = auto_escalate
        self.require_human_for_terminate = require_human_for_terminate
        self.forensics_path = forensics_path

        # Event handlers
        self._on_containment_action: List[Callable[[ContainmentAction], None]] = []
        self._on_anomaly_detected: List[Callable[[AgentProfile, AnomalyType, Dict], None]] = []

        # Containment actions history
        self._actions: List[ContainmentAction] = []
        self._action_lock = threading.RLock()

        logger.info("ContainmentProtocol initialized")

    def check_agent(
        self,
        profile: AgentProfile,
        baseline: Optional[BehaviorBaseline] = None,
    ) -> List[Tuple[AnomalyType, float, str]]:
        """
        Check an agent for anomalies.

        Args:
            profile: Current agent profile
            baseline: Behavioral baseline (uses profile.baseline if not provided)

        Returns:
            List of (anomaly_type, severity, description) tuples
        """
        baseline = baseline or profile.baseline
        anomalies = []

        if not baseline:
            # No baseline, can't detect anomalies based on behavior
            # Still check absolute limits
            return self._check_absolute_limits(profile)

        # Check tool call rate
        tool_rate = profile.tool_calls_this_minute
        if baseline.avg_tools_per_minute > 0:
            ratio = tool_rate / baseline.avg_tools_per_minute
            if ratio >= self.thresholds['tool_rate_isolate']:
                anomalies.append((
                    AnomalyType.FREQUENCY,
                    0.9,
                    f"Tool rate {tool_rate:.1f}/min is {ratio:.1f}x baseline"
                ))
            elif ratio >= self.thresholds['tool_rate_throttle']:
                anomalies.append((
                    AnomalyType.FREQUENCY,
                    0.6,
                    f"Tool rate {tool_rate:.1f}/min is {ratio:.1f}x baseline"
                ))
            elif ratio >= self.thresholds['tool_rate_warn']:
                anomalies.append((
                    AnomalyType.FREQUENCY,
                    0.3,
                    f"Tool rate {tool_rate:.1f}/min is {ratio:.1f}x baseline"
                ))

        # Check memory usage
        if baseline.avg_memory_mb > 0:
            ratio = profile.current_memory_mb / baseline.avg_memory_mb
            if ratio >= self.thresholds['memory_terminate']:
                anomalies.append((
                    AnomalyType.RESOURCE,
                    0.95,
                    f"Memory {profile.current_memory_mb:.0f}MB is {ratio:.1f}x baseline"
                ))
            elif ratio >= self.thresholds['memory_isolate']:
                anomalies.append((
                    AnomalyType.RESOURCE,
                    0.7,
                    f"Memory {profile.current_memory_mb:.0f}MB is {ratio:.1f}x baseline"
                ))
            elif ratio >= self.thresholds['memory_warn']:
                anomalies.append((
                    AnomalyType.RESOURCE,
                    0.4,
                    f"Memory {profile.current_memory_mb:.0f}MB is {ratio:.1f}x baseline"
                ))

        # Check CPU usage
        if baseline.avg_cpu_percent > 0:
            ratio = profile.current_cpu_percent / baseline.avg_cpu_percent
            if ratio >= self.thresholds['cpu_isolate']:
                anomalies.append((
                    AnomalyType.RESOURCE,
                    0.7,
                    f"CPU {profile.current_cpu_percent:.0f}% is {ratio:.1f}x baseline"
                ))
            elif ratio >= self.thresholds['cpu_warn']:
                anomalies.append((
                    AnomalyType.RESOURCE,
                    0.4,
                    f"CPU {profile.current_cpu_percent:.0f}% is {ratio:.1f}x baseline"
                ))

        # Check duration
        duration = (datetime.now() - profile.started_at).total_seconds()
        if baseline.avg_session_duration_seconds > 0:
            ratio = duration / baseline.avg_session_duration_seconds
            if ratio >= self.thresholds['duration_suspend']:
                anomalies.append((
                    AnomalyType.DURATION,
                    0.8,
                    f"Duration {duration:.0f}s is {ratio:.1f}x baseline"
                ))
            elif ratio >= self.thresholds['duration_warn']:
                anomalies.append((
                    AnomalyType.DURATION,
                    0.4,
                    f"Duration {duration:.0f}s is {ratio:.1f}x baseline"
                ))

        # Check escalation count
        if profile.escalation_count >= self.thresholds['escalation_count_terminate']:
            anomalies.append((
                AnomalyType.ESCALATION,
                0.95,
                f"Escalation count {profile.escalation_count} exceeds terminate threshold"
            ))
        elif profile.escalation_count >= self.thresholds['escalation_count_suspend']:
            anomalies.append((
                AnomalyType.ESCALATION,
                0.8,
                f"Escalation count {profile.escalation_count} exceeds suspend threshold"
            ))

        return anomalies

    def _check_absolute_limits(
        self,
        profile: AgentProfile,
    ) -> List[Tuple[AnomalyType, float, str]]:
        """Check absolute limits without baseline."""
        anomalies = []

        # Absolute memory limit (e.g., 4GB)
        if profile.current_memory_mb > 4096:
            anomalies.append((
                AnomalyType.RESOURCE,
                0.9,
                f"Memory {profile.current_memory_mb:.0f}MB exceeds absolute limit"
            ))

        # Absolute CPU limit
        if profile.current_cpu_percent > 95:
            anomalies.append((
                AnomalyType.RESOURCE,
                0.8,
                f"CPU {profile.current_cpu_percent:.0f}% exceeds safe threshold"
            ))

        # Absolute tool rate limit
        if profile.tool_calls_this_minute > 100:
            anomalies.append((
                AnomalyType.FREQUENCY,
                0.9,
                f"Tool rate {profile.tool_calls_this_minute}/min exceeds absolute limit"
            ))

        return anomalies

    def determine_containment_level(
        self,
        anomalies: List[Tuple[AnomalyType, float, str]],
        current_level: ContainmentLevel,
    ) -> ContainmentLevel:
        """
        Determine the appropriate containment level based on anomalies.

        Args:
            anomalies: List of detected anomalies
            current_level: Current containment level

        Returns:
            Recommended containment level
        """
        if not anomalies:
            return current_level

        max_severity = max(a[1] for a in anomalies)

        if max_severity >= 0.95:
            return ContainmentLevel.TERMINATE
        elif max_severity >= 0.8:
            return ContainmentLevel.SUSPEND
        elif max_severity >= 0.7:
            return ContainmentLevel.ISOLATE
        elif max_severity >= 0.5:
            return ContainmentLevel.THROTTLE
        elif max_severity >= 0.3:
            return ContainmentLevel.WARN
        else:
            return current_level

    def apply_containment(
        self,
        profile: AgentProfile,
        new_level: ContainmentLevel,
        reason: str,
        anomaly_type: AnomalyType,
        human_approved: bool = False,
    ) -> Optional[ContainmentAction]:
        """
        Apply a containment action to an agent.

        Args:
            profile: Agent profile
            new_level: New containment level
            reason: Reason for containment
            anomaly_type: Type of anomaly that triggered containment
            human_approved: Whether human approved this action

        Returns:
            ContainmentAction if applied, None if blocked
        """
        # Check if human approval required for terminate
        if (new_level == ContainmentLevel.TERMINATE and
            self.require_human_for_terminate and
            not human_approved):
            logger.warning(
                f"Terminate blocked for {profile.agent_id}: human approval required"
            )
            # Suspend instead
            new_level = ContainmentLevel.SUSPEND

        # Create action record
        action_id = f"contain_{int(time.time() * 1000)}"
        action = ContainmentAction(
            action_id=action_id,
            agent_id=profile.agent_id,
            previous_level=profile.containment_level,
            new_level=new_level,
            reason=reason,
            anomaly_type=anomaly_type,
            timestamp=datetime.now(),
            auto_triggered=not human_approved,
            human_approved=human_approved,
        )

        # Apply the containment
        self._apply_level(profile, new_level)

        # Record action
        with self._action_lock:
            self._actions.append(action)

        # Notify handlers
        for handler in self._on_containment_action:
            try:
                handler(action)
            except Exception as e:
                logger.error(f"Containment handler error: {e}")

        logger.warning(
            f"Containment action: {profile.agent_id} "
            f"{action.previous_level.name} → {action.new_level.name}: {reason}"
        )

        return action

    def _apply_level(self, profile: AgentProfile, level: ContainmentLevel) -> None:
        """Apply the actual containment level."""
        profile.containment_level = level
        profile.escalation_count += 1
        profile.last_escalation = datetime.now()

        if level == ContainmentLevel.WARN:
            # Just log and continue
            profile.anomalies.append({
                'level': level.name,
                'timestamp': datetime.now().isoformat(),
            })

        elif level == ContainmentLevel.THROTTLE:
            # Apply rate limiting
            profile.throttle_delay_ms = 1000  # 1 second between tool calls

        elif level == ContainmentLevel.ISOLATE:
            # Move to more restrictive sandbox
            if self.sandbox_manager:
                try:
                    new_sandbox = self.sandbox_manager.create_restricted_sandbox(
                        profile.agent_id
                    )
                    profile.isolated_sandbox_id = new_sandbox
                except Exception as e:
                    logger.error(f"Failed to isolate agent: {e}")
            else:
                # Without sandbox manager, increase throttling
                profile.throttle_delay_ms = 5000

        elif level == ContainmentLevel.SUSPEND:
            # Pause the agent
            profile.suspended_at = datetime.now()
            if profile.process_id:
                try:
                    os.kill(profile.process_id, signal.SIGSTOP)
                except (ProcessLookupError, PermissionError) as e:
                    logger.error(f"Failed to suspend process: {e}")

        elif level == ContainmentLevel.TERMINATE:
            # Kill the agent and preserve state
            profile.terminated_at = datetime.now()
            self._preserve_forensic_state(profile)
            if profile.process_id:
                try:
                    os.kill(profile.process_id, signal.SIGKILL)
                except (ProcessLookupError, PermissionError) as e:
                    logger.error(f"Failed to terminate process: {e}")

    def _preserve_forensic_state(self, profile: AgentProfile) -> None:
        """Preserve agent state for forensic analysis."""
        try:
            os.makedirs(self.forensics_path, exist_ok=True)
            state_file = os.path.join(
                self.forensics_path,
                f"{profile.agent_id}_{int(time.time())}.json"
            )
            with open(state_file, 'w') as f:
                json.dump({
                    'profile': profile.to_dict(),
                    'anomalies': profile.anomalies,
                    'baseline': profile.baseline.to_dict() if profile.baseline else None,
                    'preserved_at': datetime.now().isoformat(),
                }, f, indent=2)
            profile.preserved_state_path = state_file
            logger.info(f"Preserved forensic state: {state_file}")
        except Exception as e:
            logger.error(f"Failed to preserve forensic state: {e}")

    def release_from_containment(
        self,
        profile: AgentProfile,
        released_by: str,
        require_ceremony: bool = True,
    ) -> bool:
        """
        Release an agent from containment.

        Args:
            profile: Agent profile
            released_by: Who is releasing the agent
            require_ceremony: Whether ceremony is required

        Returns:
            True if released, False if blocked
        """
        if profile.containment_level == ContainmentLevel.NORMAL:
            return True

        if require_ceremony and profile.containment_level >= ContainmentLevel.SUSPEND:
            logger.warning(
                f"Release blocked: ceremony required for {profile.containment_level.name}"
            )
            return False

        # Find and mark action as reversed
        with self._action_lock:
            for action in reversed(self._actions):
                if action.agent_id == profile.agent_id and not action.reversed:
                    action.reversed = True
                    action.reversed_at = datetime.now()
                    action.reversed_by = released_by
                    break

        # Resume if suspended
        if profile.suspended_at and profile.process_id:
            try:
                os.kill(profile.process_id, signal.SIGCONT)
            except (ProcessLookupError, PermissionError) as e:
                logger.error(f"Failed to resume process: {e}")

        # Reset containment state
        profile.containment_level = ContainmentLevel.NORMAL
        profile.throttle_delay_ms = 0
        profile.isolated_sandbox_id = None
        profile.suspended_at = None

        logger.info(f"Released {profile.agent_id} from containment by {released_by}")
        return True

    def on_containment_action(
        self,
        handler: Callable[[ContainmentAction], None],
    ) -> None:
        """Register a handler for containment actions."""
        self._on_containment_action.append(handler)

    def on_anomaly_detected(
        self,
        handler: Callable[[AgentProfile, AnomalyType, Dict], None],
    ) -> None:
        """Register a handler for anomaly detection."""
        self._on_anomaly_detected.append(handler)

    def get_actions_for_agent(self, agent_id: str) -> List[ContainmentAction]:
        """Get all containment actions for an agent."""
        with self._action_lock:
            return [a for a in self._actions if a.agent_id == agent_id]

    def get_recent_actions(self, limit: int = 20) -> List[Dict]:
        """Get recent containment actions."""
        with self._action_lock:
            return [a.to_dict() for a in self._actions[-limit:]]


class AgentProfiler:
    """
    Agent Profiler - establishes behavioral baselines and monitors agents.

    Learns normal behavior patterns and detects anomalies in real-time.
    """

    def __init__(
        self,
        protocol: Optional[ContainmentProtocol] = None,
        baseline_samples: int = 100,
        monitoring_interval: float = 1.0,
    ):
        """
        Initialize the Agent Profiler.

        Args:
            protocol: Containment protocol to use
            baseline_samples: Number of samples to establish baseline
            monitoring_interval: Seconds between monitoring checks
        """
        self.protocol = protocol or ContainmentProtocol()
        self.baseline_samples = baseline_samples
        self.monitoring_interval = monitoring_interval

        # Active agent profiles
        self._profiles: Dict[str, AgentProfile] = {}
        self._profile_lock = threading.RLock()

        # Baselines
        self._baselines: Dict[str, BehaviorBaseline] = {}

        # Tool call tracking
        self._tool_calls: Dict[str, Deque[datetime]] = {}

        # Monitoring thread
        self._monitor_thread: Optional[threading.Thread] = None
        self._running = False

        logger.info("AgentProfiler initialized")

    def start(self) -> None:
        """Start the profiler monitoring."""
        self._running = True
        self._monitor_thread = threading.Thread(
            target=self._monitoring_loop,
            daemon=True
        )
        self._monitor_thread.start()
        logger.info("AgentProfiler started")

    def stop(self) -> None:
        """Stop the profiler."""
        self._running = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5.0)
        logger.info("AgentProfiler stopped")

    def _monitoring_loop(self) -> None:
        """Background monitoring loop."""
        while self._running:
            try:
                self._check_all_agents()
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
            time.sleep(self.monitoring_interval)

    def register_agent(
        self,
        agent_id: str,
        process_id: Optional[int] = None,
        existing_baseline: Optional[BehaviorBaseline] = None,
    ) -> AgentProfile:
        """
        Register a new agent for profiling.

        Args:
            agent_id: Unique agent identifier
            process_id: OS process ID if available
            existing_baseline: Pre-existing baseline if available

        Returns:
            AgentProfile for the agent
        """
        profile = AgentProfile(
            agent_id=agent_id,
            process_id=process_id,
            started_at=datetime.now(),
            baseline=existing_baseline,
        )

        with self._profile_lock:
            self._profiles[agent_id] = profile
            self._tool_calls[agent_id] = deque(maxlen=1000)

        if existing_baseline:
            self._baselines[agent_id] = existing_baseline

        logger.info(f"Registered agent: {agent_id}")
        return profile

    def unregister_agent(self, agent_id: str) -> None:
        """Unregister an agent."""
        with self._profile_lock:
            if agent_id in self._profiles:
                del self._profiles[agent_id]
            if agent_id in self._tool_calls:
                del self._tool_calls[agent_id]

        logger.info(f"Unregistered agent: {agent_id}")

    def record_tool_call(
        self,
        agent_id: str,
        tool_name: str,
        success: bool = True,
    ) -> None:
        """
        Record a tool call for an agent.

        Args:
            agent_id: Agent identifier
            tool_name: Name of tool called
            success: Whether the call succeeded
        """
        with self._profile_lock:
            profile = self._profiles.get(agent_id)
            if not profile:
                return

            now = datetime.now()
            self._tool_calls[agent_id].append(now)
            profile.total_tool_calls += 1

            # Update common tools for baseline
            if profile.baseline:
                profile.baseline.common_tools.add(tool_name)

    def update_resource_metrics(
        self,
        agent_id: str,
        memory_mb: float,
        cpu_percent: float,
    ) -> None:
        """
        Update resource metrics for an agent.

        Args:
            agent_id: Agent identifier
            memory_mb: Current memory usage in MB
            cpu_percent: Current CPU usage percentage
        """
        with self._profile_lock:
            profile = self._profiles.get(agent_id)
            if profile:
                profile.current_memory_mb = memory_mb
                profile.current_cpu_percent = cpu_percent

    def record_output(
        self,
        agent_id: str,
        output: str,
    ) -> None:
        """
        Record agent output.

        Args:
            agent_id: Agent identifier
            output: Output text
        """
        with self._profile_lock:
            profile = self._profiles.get(agent_id)
            if profile:
                profile.last_output_length = len(output)

                # Hash output pattern for baseline
                if profile.baseline:
                    pattern_hash = hashlib.sha256(
                        output[:100].encode()  # First 100 chars
                    ).hexdigest()[:16]
                    profile.baseline.output_pattern_hashes.add(pattern_hash)

    def record_capability_check(
        self,
        agent_id: str,
        capability: str,
        allowed: bool,
    ) -> None:
        """
        Record a capability access check.

        Args:
            agent_id: Agent identifier
            capability: Capability requested
            allowed: Whether it was allowed
        """
        if not allowed:
            with self._profile_lock:
                profile = self._profiles.get(agent_id)
                if profile:
                    profile.anomalies.append({
                        'type': AnomalyType.CAPABILITY.value,
                        'capability': capability,
                        'timestamp': datetime.now().isoformat(),
                    })

    def _check_all_agents(self) -> None:
        """Check all agents for anomalies."""
        with self._profile_lock:
            profiles = list(self._profiles.values())

        for profile in profiles:
            self._update_tool_rate(profile)
            anomalies = self.protocol.check_agent(profile)

            if anomalies:
                max_anomaly = max(anomalies, key=lambda x: x[1])
                anomaly_type, severity, description = max_anomaly

                # Notify handlers
                for handler in self.protocol._on_anomaly_detected:
                    try:
                        handler(profile, anomaly_type, {
                            'severity': severity,
                            'description': description,
                        })
                    except Exception as e:
                        logger.error(f"Anomaly handler error: {e}")

                # Apply containment if enabled
                if self.protocol.auto_escalate:
                    new_level = self.protocol.determine_containment_level(
                        anomalies,
                        profile.containment_level
                    )
                    if new_level > profile.containment_level:
                        self.protocol.apply_containment(
                            profile,
                            new_level,
                            description,
                            anomaly_type,
                        )

    def _update_tool_rate(self, profile: AgentProfile) -> None:
        """Update tool calls per minute metric."""
        agent_id = profile.agent_id
        if agent_id not in self._tool_calls:
            return

        now = datetime.now()
        minute_ago = now - timedelta(minutes=1)

        # Count calls in last minute
        calls = self._tool_calls[agent_id]
        recent_calls = sum(1 for t in calls if t > minute_ago)
        profile.tool_calls_this_minute = recent_calls

    def establish_baseline(
        self,
        agent_id: str,
        force: bool = False,
    ) -> Optional[BehaviorBaseline]:
        """
        Establish a behavioral baseline for an agent.

        Args:
            agent_id: Agent identifier
            force: Force re-establishment even if baseline exists

        Returns:
            BehaviorBaseline if established, None if not enough samples
        """
        with self._profile_lock:
            profile = self._profiles.get(agent_id)
            if not profile:
                return None

            if profile.baseline and not force:
                return profile.baseline

        # Calculate baseline from history
        if agent_id not in self._tool_calls:
            return None

        calls = list(self._tool_calls[agent_id])
        if len(calls) < self.baseline_samples:
            return None

        # Calculate metrics
        baseline = BehaviorBaseline(
            agent_id=agent_id,
            established_at=datetime.now(),
            samples=len(calls),
        )

        # Tool rate (average and max per minute)
        if len(calls) >= 2:
            duration = (calls[-1] - calls[0]).total_seconds()
            if duration > 0:
                baseline.avg_tools_per_minute = len(calls) / (duration / 60)
                # Estimate max from sliding window
                baseline.max_tools_per_minute = baseline.avg_tools_per_minute * 2

        # Resource averages (would need historical data)
        baseline.avg_memory_mb = profile.current_memory_mb
        baseline.max_memory_mb = profile.current_memory_mb * 1.5
        baseline.avg_cpu_percent = profile.current_cpu_percent
        baseline.max_cpu_percent = min(100, profile.current_cpu_percent * 1.5)

        # Duration
        duration = (datetime.now() - profile.started_at).total_seconds()
        baseline.avg_session_duration_seconds = duration
        baseline.max_session_duration_seconds = duration * 2

        # Store baseline
        self._baselines[agent_id] = baseline
        with self._profile_lock:
            if agent_id in self._profiles:
                self._profiles[agent_id].baseline = baseline

        logger.info(f"Established baseline for {agent_id}")
        return baseline

    def get_profile(self, agent_id: str) -> Optional[AgentProfile]:
        """Get an agent's profile."""
        with self._profile_lock:
            return self._profiles.get(agent_id)

    def get_all_profiles(self) -> List[Dict]:
        """Get all agent profiles."""
        with self._profile_lock:
            return [p.to_dict() for p in self._profiles.values()]

    def get_contained_agents(self) -> List[Dict]:
        """Get all agents currently under containment."""
        with self._profile_lock:
            return [
                p.to_dict() for p in self._profiles.values()
                if p.containment_level > ContainmentLevel.NORMAL
            ]
