"""
Sandbox Manager for Boundary Daemon

Orchestrates all sandbox components:
- Linux namespace isolation
- Seccomp-bpf syscall filtering
- Cgroups v2 resource limits
- Policy engine integration
- Ceremony system integration

The sandbox manager provides:
1. Policy-driven sandboxing based on boundary mode
2. Break-glass capability via ceremony system
3. Real-time monitoring and enforcement
4. Integration with eBPF observer

Usage:
    from daemon.sandbox import SandboxManager, SandboxProfile
    from daemon.policy_engine import PolicyEngine, BoundaryMode

    policy_engine = PolicyEngine(initial_mode=BoundaryMode.RESTRICTED)
    manager = SandboxManager(policy_engine)

    # Run a command in policy-appropriate sandbox
    result = manager.run_sandboxed(
        command=["python3", "untrusted_script.py"],
    )

    # Or create a persistent sandbox
    sandbox = manager.create_sandbox(name="worker-1")
    sandbox.run(["./process_data.sh"])
    sandbox.terminate()
"""

import logging
import os
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .namespace import (
    NamespaceManager,
    NamespaceFlags,
    NamespaceConfig,
    IsolatedProcess,
)
from .seccomp_filter import (
    SeccompFilter,
    SeccompProfiles,
    SeccompProfile,
)
from .cgroups import (
    CgroupManager,
    CgroupLimits,
    CgroupError,
    ResourceUsage,
)
from .network_policy import (
    NetworkPolicy,
    SandboxFirewall,
    get_sandbox_firewall,
)

logger = logging.getLogger(__name__)


class SandboxState(Enum):
    """State of a sandbox."""
    CREATED = auto()
    RUNNING = auto()
    PAUSED = auto()
    STOPPED = auto()
    FAILED = auto()


class SandboxError(Exception):
    """Error during sandbox operations."""
    pass


@dataclass
class SandboxProfile:
    """
    Complete sandbox profile combining all isolation mechanisms.

    Profiles are matched to boundary modes:
    - OPEN: Minimal isolation (basic resource limits)
    - RESTRICTED: Namespace isolation (PID, mount)
    - TRUSTED: Full namespace isolation + basic seccomp
    - AIRGAP: Strict network isolation + filesystem restrictions
    - COLDROOM: Maximum isolation, minimal syscalls
    - LOCKDOWN: No execution allowed
    """
    name: str
    description: str = ""

    # Namespace configuration
    namespace_flags: NamespaceFlags = NamespaceFlags.STANDARD
    namespace_config: Optional[NamespaceConfig] = None

    # Seccomp profile
    seccomp_profile: Optional[SeccompProfile] = None
    seccomp_enabled: bool = True

    # Cgroup limits
    cgroup_limits: Optional[CgroupLimits] = None
    cgroup_enabled: bool = True

    # Additional restrictions
    readonly_filesystem: bool = False
    no_new_privileges: bool = True
    drop_capabilities: List[str] = field(default_factory=list)

    # Network restrictions
    network_disabled: bool = False
    allowed_hosts: List[str] = field(default_factory=list)
    network_policy: Optional[NetworkPolicy] = None  # Fine-grained firewall rules

    # Filesystem restrictions
    allowed_paths: List[str] = field(default_factory=list)
    denied_paths: List[str] = field(default_factory=list)
    temp_size_mb: int = 100

    # Process restrictions
    max_processes: int = 100
    max_runtime_seconds: Optional[int] = None

    @classmethod
    def minimal(cls) -> 'SandboxProfile':
        """Minimal profile - basic resource limits only."""
        return cls(
            name="minimal",
            description="Basic resource limits, minimal isolation",
            namespace_flags=NamespaceFlags.NONE,
            seccomp_enabled=False,
            cgroup_limits=CgroupLimits.unrestricted(),
        )

    @classmethod
    def standard(cls) -> 'SandboxProfile':
        """Standard profile - namespace isolation + resource limits."""
        return cls(
            name="standard",
            description="Namespace isolation with resource limits",
            namespace_flags=NamespaceFlags.STANDARD,
            seccomp_profile=SeccompProfiles.standard(),
            cgroup_limits=CgroupLimits.standard(),
        )

    @classmethod
    def strict(cls) -> 'SandboxProfile':
        """Strict profile - full isolation."""
        return cls(
            name="strict",
            description="Full isolation for untrusted code",
            namespace_flags=NamespaceFlags.FULL,
            seccomp_profile=SeccompProfiles.untrusted(),
            cgroup_limits=CgroupLimits.minimal(),
            readonly_filesystem=True,
            network_disabled=True,
            max_runtime_seconds=60,
        )

    @classmethod
    def from_boundary_mode(cls, mode: int) -> 'SandboxProfile':
        """
        Create a profile appropriate for a boundary mode.

        Args:
            mode: Boundary mode (0=OPEN to 5=LOCKDOWN)
        """
        if mode >= 5:  # LOCKDOWN
            return cls(
                name="lockdown",
                description="No execution allowed (lockdown mode)",
                namespace_flags=NamespaceFlags.MAXIMUM,
                seccomp_profile=SeccompProfiles.for_boundary_mode(5),
                cgroup_limits=CgroupLimits.for_boundary_mode(5),
                readonly_filesystem=True,
                network_disabled=True,
                network_policy=NetworkPolicy.for_boundary_mode(5),
                max_processes=1,
                max_runtime_seconds=1,
            )
        elif mode >= 4:  # COLDROOM
            return cls(
                name="coldroom",
                description="Maximum isolation for coldroom mode",
                namespace_flags=NamespaceFlags.FULL,
                seccomp_profile=SeccompProfiles.for_boundary_mode(4),
                cgroup_limits=CgroupLimits.for_boundary_mode(4),
                readonly_filesystem=True,
                network_disabled=True,
                network_policy=NetworkPolicy.for_boundary_mode(4),
                max_runtime_seconds=300,
            )
        elif mode >= 3:  # AIRGAP
            return cls(
                name="airgap",
                description="Network-isolated sandbox for airgap mode",
                namespace_flags=NamespaceFlags.FULL,
                seccomp_profile=SeccompProfiles.for_boundary_mode(3),
                cgroup_limits=CgroupLimits.for_boundary_mode(3),
                network_disabled=True,
                network_policy=NetworkPolicy.for_boundary_mode(3),
            )
        elif mode >= 2:  # TRUSTED
            return cls(
                name="trusted",
                description="Standard isolation for trusted mode",
                namespace_flags=NamespaceFlags.STANDARD,
                seccomp_profile=SeccompProfiles.for_boundary_mode(2),
                cgroup_limits=CgroupLimits.for_boundary_mode(2),
                network_policy=NetworkPolicy.for_boundary_mode(2),
            )
        elif mode >= 1:  # RESTRICTED
            return cls(
                name="restricted",
                description="Light isolation for restricted mode",
                namespace_flags=NamespaceFlags.MINIMAL,
                seccomp_profile=SeccompProfiles.for_boundary_mode(1),
                cgroup_limits=CgroupLimits.for_boundary_mode(1),
                network_policy=NetworkPolicy.for_boundary_mode(1),
            )
        else:  # OPEN
            return cls.minimal()


@dataclass
class SandboxResult:
    """Result of a sandboxed command execution."""
    sandbox_id: str
    command: List[str]
    exit_code: int
    stdout: str
    stderr: str
    runtime_seconds: float
    resource_usage: Optional[ResourceUsage] = None
    killed: bool = False
    kill_reason: str = ""
    started_at: datetime = field(default_factory=datetime.utcnow)
    ended_at: Optional[datetime] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            'sandbox_id': self.sandbox_id,
            'command': self.command,
            'exit_code': self.exit_code,
            'stdout_length': len(self.stdout),
            'stderr_length': len(self.stderr),
            'runtime_seconds': self.runtime_seconds,
            'resource_usage': self.resource_usage.to_dict() if self.resource_usage else None,
            'killed': self.killed,
            'kill_reason': self.kill_reason,
            'started_at': self.started_at.isoformat(),
            'ended_at': self.ended_at.isoformat() if self.ended_at else None,
        }


class Sandbox:
    """
    A single sandbox instance.

    Provides a containerized execution environment with:
    - Process isolation via namespaces
    - Syscall filtering via seccomp
    - Resource limits via cgroups
    """

    def __init__(
        self,
        sandbox_id: str,
        profile: SandboxProfile,
        namespace_manager: NamespaceManager,
        cgroup_manager: CgroupManager,
        sandbox_firewall: Optional[SandboxFirewall] = None,
        event_callback: Optional[Callable[[str, Dict], None]] = None,
    ):
        self.sandbox_id = sandbox_id
        self._profile = profile
        self._namespace_manager = namespace_manager
        self._cgroup_manager = cgroup_manager
        self._sandbox_firewall = sandbox_firewall
        self._event_callback = event_callback

        self._state = SandboxState.CREATED
        self._process: Optional[IsolatedProcess] = None
        self._cgroup_path: Optional[Path] = None
        self._firewall_applied = False
        self._created_at = datetime.utcnow()
        self._started_at: Optional[datetime] = None
        self._ended_at: Optional[datetime] = None

        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_monitor = threading.Event()

    @property
    def state(self) -> SandboxState:
        """Get current sandbox state."""
        return self._state

    @property
    def profile(self) -> SandboxProfile:
        """Get sandbox profile."""
        return self._profile

    def _emit_event(self, event_type: str, data: Dict) -> None:
        """Emit a sandbox event."""
        if self._event_callback:
            try:
                data['sandbox_id'] = self.sandbox_id
                data['timestamp'] = datetime.utcnow().isoformat()
                self._event_callback(event_type, data)
            except Exception as e:
                logger.error(f"Event callback failed: {e}")

    def _setup_cgroup(self) -> None:
        """Set up cgroup for the sandbox."""
        if not self._profile.cgroup_enabled:
            return

        if not self._cgroup_manager.can_manage_cgroups():
            logger.warning("Cgroups not available, skipping resource limits")
            return

        try:
            self._cgroup_path = self._cgroup_manager.create_cgroup(self.sandbox_id)

            if self._profile.cgroup_limits:
                self._cgroup_manager.set_limits(
                    self._cgroup_path,
                    self._profile.cgroup_limits,
                )

            logger.debug(f"Cgroup setup complete: {self._cgroup_path}")

        except CgroupError as e:
            logger.warning(f"Could not setup cgroup: {e}")

    def _setup_firewall(self) -> None:
        """Set up firewall rules for the sandbox."""
        if not self._sandbox_firewall:
            return

        if not self._profile.network_policy:
            # If no explicit policy but network_disabled, create deny policy
            if self._profile.network_disabled:
                policy = NetworkPolicy.allow_none()
            else:
                return  # No restrictions

        else:
            policy = self._profile.network_policy

        # Need cgroup path for cgroup-based firewall rules
        if not self._cgroup_path:
            logger.warning("No cgroup path, firewall rules may not be sandbox-specific")
            return

        success, msg = self._sandbox_firewall.setup_sandbox_rules(
            sandbox_id=self.sandbox_id,
            cgroup_path=self._cgroup_path,
            policy=policy,
        )

        if success:
            self._firewall_applied = True
            logger.debug(f"Firewall rules applied: {msg}")
        else:
            logger.warning(f"Could not setup firewall: {msg}")

    def _cleanup_firewall(self) -> None:
        """Clean up firewall rules for the sandbox."""
        if not self._sandbox_firewall or not self._firewall_applied:
            return

        success, msg = self._sandbox_firewall.cleanup_sandbox_rules(self.sandbox_id)
        if success:
            self._firewall_applied = False
            logger.debug(f"Firewall rules cleaned up: {msg}")
        else:
            logger.warning(f"Could not cleanup firewall: {msg}")

    def _build_namespace_config(self) -> NamespaceConfig:
        """Build namespace configuration from profile."""
        config = self._profile.namespace_config or NamespaceConfig()

        config.flags = self._profile.namespace_flags
        config.readonly_root = self._profile.readonly_filesystem

        # Add denied paths to readonly mounts
        if self._profile.denied_paths:
            config.readonly_mounts = list(self._profile.denied_paths)

        return config

    def _monitor_process(self) -> None:
        """Monitor running process for resource usage and timeout."""
        start_time = time.time()

        while not self._stop_monitor.is_set() and self._process:
            # Check if process is still running
            if self._process.poll() is not None:
                break

            # Check timeout
            if self._profile.max_runtime_seconds:
                elapsed = time.time() - start_time
                if elapsed > self._profile.max_runtime_seconds:
                    logger.warning(f"Sandbox {self.sandbox_id} exceeded max runtime")
                    self.terminate(reason="timeout")
                    break

            # Check resource usage
            if self._cgroup_path:
                usage = self._cgroup_manager.get_usage(self._cgroup_path)

                # Emit usage event periodically
                self._emit_event('resource_usage', usage.to_dict())

            time.sleep(1)

    def run(
        self,
        command: List[str],
        env: Optional[Dict[str, str]] = None,
        stdin: Optional[bytes] = None,
        capture_output: bool = True,
        timeout: Optional[float] = None,
    ) -> SandboxResult:
        """
        Run a command in the sandbox.

        Args:
            command: Command and arguments
            env: Environment variables
            stdin: Input to send to process
            capture_output: Whether to capture stdout/stderr
            timeout: Override timeout (seconds)

        Returns:
            SandboxResult with execution details
        """
        if self._state not in (SandboxState.CREATED, SandboxState.STOPPED):
            raise SandboxError(f"Cannot run in state: {self._state}")

        self._state = SandboxState.RUNNING
        self._started_at = datetime.utcnow()

        self._emit_event('sandbox_start', {
            'command': command,
            'profile': self._profile.name,
        })

        try:
            # Set up cgroup
            self._setup_cgroup()

            # Set up firewall rules (after cgroup so we have cgroup path)
            self._setup_firewall()

            # Build namespace config
            ns_config = self._build_namespace_config()

            # Create isolated process
            stdout_pipe = subprocess.PIPE if capture_output else None
            stderr_pipe = subprocess.PIPE if capture_output else None
            stdin_pipe = subprocess.PIPE if stdin else None

            self._process = self._namespace_manager.create_isolated_process(
                command=command,
                config=ns_config,
                env=env,
                stdin=stdin_pipe,
                stdout=stdout_pipe,
                stderr=stderr_pipe,
            )

            # Add process to cgroup
            if self._cgroup_path and self._process.pid:
                self._cgroup_manager.add_process(
                    self._cgroup_path,
                    self._process.pid,
                )

            # Start monitor thread
            self._stop_monitor.clear()
            self._monitor_thread = threading.Thread(
                target=self._monitor_process,
                daemon=True,
            )
            self._monitor_thread.start()

            # Determine timeout
            effective_timeout = timeout or self._profile.max_runtime_seconds

            # Wait for completion
            try:
                stdout_data, stderr_data = self._process.communicate(
                    input=stdin,
                    timeout=effective_timeout,
                )
            except subprocess.TimeoutExpired:
                self.terminate(reason="timeout")
                stdout_data, stderr_data = b'', b''

            # Stop monitor
            self._stop_monitor.set()
            if self._monitor_thread:
                self._monitor_thread.join(timeout=1)

            # Get final resource usage
            resource_usage = None
            if self._cgroup_path:
                resource_usage = self._cgroup_manager.get_usage(self._cgroup_path)

            self._ended_at = datetime.utcnow()
            runtime = (self._ended_at - self._started_at).total_seconds()

            result = SandboxResult(
                sandbox_id=self.sandbox_id,
                command=command,
                exit_code=self._process.returncode or 0,
                stdout=stdout_data.decode('utf-8', errors='replace') if stdout_data else '',
                stderr=stderr_data.decode('utf-8', errors='replace') if stderr_data else '',
                runtime_seconds=runtime,
                resource_usage=resource_usage,
                started_at=self._started_at,
                ended_at=self._ended_at,
            )

            self._state = SandboxState.STOPPED

            self._emit_event('sandbox_stop', {
                'exit_code': result.exit_code,
                'runtime_seconds': runtime,
            })

            return result

        except Exception as e:
            self._state = SandboxState.FAILED
            self._emit_event('sandbox_error', {'error': str(e)})
            raise SandboxError(f"Sandbox execution failed: {e}")

    def terminate(self, reason: str = "user request") -> None:
        """
        Terminate the sandbox and all its processes.

        Args:
            reason: Reason for termination
        """
        logger.info(f"Terminating sandbox {self.sandbox_id}: {reason}")

        self._emit_event('sandbox_terminate', {'reason': reason})

        # Stop monitor
        self._stop_monitor.set()

        # Kill the process
        if self._process:
            try:
                self._process.kill()
            except Exception:
                pass

        # Kill all processes in cgroup
        if self._cgroup_path:
            try:
                procs = self._cgroup_manager.get_processes(self._cgroup_path)
                for pid in procs:
                    try:
                        os.kill(pid, 9)
                    except ProcessLookupError:
                        pass
            except Exception:
                pass

        self._state = SandboxState.STOPPED

    def pause(self) -> bool:
        """Pause the sandbox (freeze all processes)."""
        if self._state != SandboxState.RUNNING:
            return False

        if self._cgroup_path:
            if self._cgroup_manager.freeze(self._cgroup_path):
                self._state = SandboxState.PAUSED
                self._emit_event('sandbox_pause', {})
                return True

        return False

    def resume(self) -> bool:
        """Resume a paused sandbox."""
        if self._state != SandboxState.PAUSED:
            return False

        if self._cgroup_path:
            if self._cgroup_manager.thaw(self._cgroup_path):
                self._state = SandboxState.RUNNING
                self._emit_event('sandbox_resume', {})
                return True

        return False

    def get_usage(self) -> Optional[ResourceUsage]:
        """Get current resource usage."""
        if self._cgroup_path:
            return self._cgroup_manager.get_usage(self._cgroup_path)
        return None

    def cleanup(self) -> None:
        """Clean up sandbox resources."""
        self.terminate(reason="cleanup")

        # Clean up firewall rules first
        self._cleanup_firewall()

        if self._cgroup_path:
            try:
                self._cgroup_manager.delete_cgroup(self._cgroup_path)
            except Exception as e:
                logger.debug(f"Cgroup cleanup error: {e}")

        self._emit_event('sandbox_cleanup', {})


class SandboxManager:
    """
    Manages sandboxes with policy engine integration.

    Provides:
    - Policy-driven sandbox creation based on boundary mode
    - Ceremony integration for break-glass scenarios
    - Sandbox lifecycle management
    - Resource monitoring and enforcement
    """

    def __init__(
        self,
        policy_engine: Optional[Any] = None,  # PolicyEngine from daemon.policy_engine
        ceremony_manager: Optional[Any] = None,  # CeremonyManager for break-glass
        event_callback: Optional[Callable[[str, Dict], None]] = None,
    ):
        self._policy_engine = policy_engine
        self._ceremony_manager = ceremony_manager
        self._event_callback = event_callback

        # Initialize managers
        self._namespace_manager = NamespaceManager()
        self._cgroup_manager = CgroupManager()
        self._sandbox_firewall = get_sandbox_firewall()

        # Active sandboxes
        self._sandboxes: Dict[str, Sandbox] = {}
        self._lock = threading.Lock()

        # Stats
        self._total_created = 0
        self._total_completed = 0
        self._total_failed = 0

    def get_capabilities(self) -> Dict[str, Any]:
        """Get sandbox capabilities on this system."""
        return {
            'namespaces': self._namespace_manager.get_capabilities(),
            'cgroups': self._cgroup_manager.get_capabilities(),
            'firewall': self._sandbox_firewall.get_capabilities(),
            'can_sandbox': (
                self._namespace_manager.can_create_namespaces() or
                self._cgroup_manager.can_manage_cgroups()
            ),
        }

    def get_current_boundary_mode(self) -> int:
        """Get current boundary mode from policy engine."""
        if self._policy_engine:
            try:
                return int(self._policy_engine.get_current_mode())
            except Exception:
                pass
        return 0  # Default to OPEN

    def get_profile_for_current_mode(self) -> SandboxProfile:
        """Get sandbox profile appropriate for current boundary mode."""
        mode = self.get_current_boundary_mode()
        return SandboxProfile.from_boundary_mode(mode)

    def _check_ceremony_required(self, profile: SandboxProfile) -> Tuple[bool, str]:
        """
        Check if ceremony is required to run with given profile.

        Returns:
            (required, reason)
        """
        mode = self.get_current_boundary_mode()

        # In LOCKDOWN mode, always require ceremony
        if mode >= 5:
            return True, "LOCKDOWN mode requires ceremony for any execution"

        # In COLDROOM mode, require ceremony for non-minimal sandboxes
        if mode >= 4 and profile.name != "coldroom":
            return True, "COLDROOM mode requires ceremony for relaxed sandboxing"

        return False, ""

    def create_sandbox(
        self,
        name: Optional[str] = None,
        profile: Optional[SandboxProfile] = None,
        skip_ceremony: bool = False,
    ) -> Sandbox:
        """
        Create a new sandbox.

        Args:
            name: Optional name for the sandbox
            profile: Sandbox profile (defaults to current boundary mode profile)
            skip_ceremony: Skip ceremony check (for internal use)

        Returns:
            Sandbox instance
        """
        # Generate ID
        sandbox_id = name or f"sandbox-{uuid.uuid4().hex[:8]}"

        # Get profile
        if profile is None:
            profile = self.get_profile_for_current_mode()

        # Check ceremony requirement
        if not skip_ceremony:
            required, reason = self._check_ceremony_required(profile)
            if required:
                if self._ceremony_manager:
                    # TODO: Integrate with ceremony system
                    logger.warning(f"Ceremony required: {reason}")
                    raise SandboxError(f"Ceremony required: {reason}")
                else:
                    raise SandboxError(f"Ceremony required but not available: {reason}")

        # Create sandbox
        sandbox = Sandbox(
            sandbox_id=sandbox_id,
            profile=profile,
            namespace_manager=self._namespace_manager,
            cgroup_manager=self._cgroup_manager,
            sandbox_firewall=self._sandbox_firewall,
            event_callback=self._event_callback,
        )

        with self._lock:
            self._sandboxes[sandbox_id] = sandbox
            self._total_created += 1

        logger.info(f"Created sandbox: {sandbox_id} (profile: {profile.name})")

        return sandbox

    def run_sandboxed(
        self,
        command: List[str],
        env: Optional[Dict[str, str]] = None,
        stdin: Optional[bytes] = None,
        profile: Optional[SandboxProfile] = None,
        timeout: Optional[float] = None,
    ) -> SandboxResult:
        """
        Run a command in a temporary sandbox.

        Convenience method that creates a sandbox, runs the command,
        and cleans up automatically.

        Args:
            command: Command and arguments
            env: Environment variables
            stdin: Input to send to process
            profile: Sandbox profile (defaults to current boundary mode)
            timeout: Execution timeout

        Returns:
            SandboxResult
        """
        sandbox = self.create_sandbox(profile=profile)

        try:
            result = sandbox.run(
                command=command,
                env=env,
                stdin=stdin,
                timeout=timeout,
            )

            with self._lock:
                self._total_completed += 1

            return result

        except Exception as e:
            with self._lock:
                self._total_failed += 1
            raise

        finally:
            sandbox.cleanup()
            with self._lock:
                self._sandboxes.pop(sandbox.sandbox_id, None)

    def get_sandbox(self, sandbox_id: str) -> Optional[Sandbox]:
        """Get a sandbox by ID."""
        with self._lock:
            return self._sandboxes.get(sandbox_id)

    def list_sandboxes(self) -> List[Dict]:
        """List all active sandboxes."""
        with self._lock:
            return [
                {
                    'id': s.sandbox_id,
                    'state': s.state.name,
                    'profile': s.profile.name,
                }
                for s in self._sandboxes.values()
            ]

    def terminate_sandbox(self, sandbox_id: str, reason: str = "manager request") -> bool:
        """Terminate a sandbox by ID."""
        sandbox = self.get_sandbox(sandbox_id)
        if sandbox:
            sandbox.terminate(reason=reason)
            return True
        return False

    def terminate_all(self, reason: str = "manager shutdown") -> int:
        """Terminate all sandboxes."""
        count = 0
        with self._lock:
            for sandbox in list(self._sandboxes.values()):
                sandbox.terminate(reason=reason)
                count += 1
        return count

    def cleanup(self) -> None:
        """Clean up all sandboxes and resources."""
        self.terminate_all(reason="cleanup")

        with self._lock:
            for sandbox in list(self._sandboxes.values()):
                sandbox.cleanup()
            self._sandboxes.clear()

        self._cgroup_manager.cleanup()
        self._sandbox_firewall.cleanup_all()

    def get_stats(self) -> Dict[str, Any]:
        """Get sandbox manager statistics."""
        with self._lock:
            active_by_state = {}
            for sandbox in self._sandboxes.values():
                state = sandbox.state.name
                active_by_state[state] = active_by_state.get(state, 0) + 1

            return {
                'capabilities': self.get_capabilities(),
                'current_boundary_mode': self.get_current_boundary_mode(),
                'active_sandboxes': len(self._sandboxes),
                'active_by_state': active_by_state,
                'total_created': self._total_created,
                'total_completed': self._total_completed,
                'total_failed': self._total_failed,
            }


if __name__ == '__main__':
    print("Testing Sandbox Manager...")

    manager = SandboxManager()

    print(f"\nCapabilities: {manager.get_capabilities()}")

    # Test profile generation
    print("\nProfiles for each boundary mode:")
    for mode in range(6):
        profile = SandboxProfile.from_boundary_mode(mode)
        print(f"  Mode {mode}: {profile.name}")
        print(f"    Namespaces: {profile.namespace_flags.name}")
        print(f"    Network disabled: {profile.network_disabled}")

    # Test sandbox creation and execution
    print("\nCreating test sandbox...")
    try:
        result = manager.run_sandboxed(
            command=['echo', 'Hello from sandbox!'],
            timeout=10,
        )

        print(f"\nResult:")
        print(f"  Exit code: {result.exit_code}")
        print(f"  Stdout: {result.stdout.strip()}")
        print(f"  Runtime: {result.runtime_seconds:.3f}s")

    except SandboxError as e:
        print(f"\nSandbox error: {e}")
        print("(This is expected if namespaces are not available)")

    print(f"\nStats: {manager.get_stats()}")

    print("\nSandbox manager test complete.")
