"""
Comprehensive Pipeline Tests for All Boundary Daemon Features.

This module provides in-depth testing for each feature pipeline,
with detailed logging and verification of all component interactions.
"""

import os
import sys
import time
import tempfile
import threading
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional
from dataclasses import dataclass

# Add parent directories to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from daemon.logging_config import (
    setup_logging, get_logger, set_verbose, set_trace,
    FeatureArea, verbose_for
)


@dataclass
class PipelineTestResult:
    """Result of comprehensive pipeline test."""
    name: str
    passed: int
    failed: int
    skipped: int
    errors: List[str]
    duration_ms: float
    details: Dict[str, Any]


class ComprehensivePipelineTests:
    """Comprehensive tests for all boundary daemon pipelines."""

    def __init__(self, verbose: bool = False, trace: bool = False):
        self.verbose = verbose
        self.trace = trace
        self.logger = get_logger('tests.comprehensive')
        self.results: List[PipelineTestResult] = []
        self.temp_dir: Optional[Path] = None

    def setup(self):
        """Setup test environment."""
        self.temp_dir = Path(tempfile.mkdtemp(prefix="boundary_comprehensive_"))
        self.logger.info(f"Test environment: {self.temp_dir}")

    def teardown(self):
        """Cleanup test environment."""
        if self.temp_dir and self.temp_dir.exists():
            import shutil
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def run_all(self) -> List[PipelineTestResult]:
        """Run all comprehensive pipeline tests."""
        self.setup()

        try:
            # Core pipelines
            self.results.append(self.test_state_monitor_pipeline())
            self.results.append(self.test_policy_engine_pipeline())
            self.results.append(self.test_tripwire_pipeline())
            self.results.append(self.test_event_logger_pipeline())

            # Security pipelines
            self.results.append(self.test_security_pipeline())
            self.results.append(self.test_enforcement_pipeline())
            self.results.append(self.test_sandbox_pipeline())

            # Supporting pipelines
            self.results.append(self.test_auth_pipeline())
            self.results.append(self.test_health_pipeline())
            self.results.append(self.test_integration_pipeline())

            # End-to-end
            self.results.append(self.test_full_daemon_lifecycle())

        finally:
            self.teardown()

        return self.results

    def test_state_monitor_pipeline(self) -> PipelineTestResult:
        """Test state monitor pipeline comprehensively."""
        self.logger.info("=" * 50)
        self.logger.info("Testing State Monitor Pipeline")
        self.logger.info("=" * 50)

        start = time.perf_counter()
        passed = 0
        failed = 0
        skipped = 0
        errors = []
        details = {}

        try:
            from daemon.state_monitor import (
                StateMonitor, NetworkState, NetworkType,
                HardwareTrust, EnvironmentState
            )

            # Test 1: Instantiation with config
            self.logger.verbose("Test 1: StateMonitor instantiation")
            try:
                monitor = StateMonitor(poll_interval=0.5)
                passed += 1
                details['instantiation'] = 'passed'
            except Exception as e:
                failed += 1
                errors.append(f"instantiation: {e}")
                details['instantiation'] = f'failed: {e}'

            # Test 2: Network state detection
            self.logger.verbose("Test 2: Network state detection")
            try:
                state = monitor.get_network_state()
                assert state in (NetworkState.ONLINE, NetworkState.OFFLINE)
                passed += 1
                details['network_state'] = str(state)
            except Exception as e:
                failed += 1
                errors.append(f"network_state: {e}")

            # Test 3: All network types
            self.logger.verbose("Test 3: Network type detection")
            try:
                net_type = monitor.get_network_type()
                assert isinstance(net_type, NetworkType)
                passed += 1
                details['network_type'] = str(net_type)
            except Exception as e:
                failed += 1
                errors.append(f"network_type: {e}")

            # Test 4: Hardware trust
            self.logger.verbose("Test 4: Hardware trust assessment")
            try:
                trust = monitor.get_hardware_trust()
                assert trust in (HardwareTrust.LOW, HardwareTrust.MEDIUM, HardwareTrust.HIGH)
                passed += 1
                details['hardware_trust'] = str(trust)
            except Exception as e:
                failed += 1
                errors.append(f"hardware_trust: {e}")

            # Test 5: Environment snapshot
            self.logger.verbose("Test 5: Full environment snapshot")
            try:
                env = monitor.get_environment_state()
                assert isinstance(env, EnvironmentState)
                assert hasattr(env, 'network_state')
                assert hasattr(env, 'hardware_trust')
                passed += 1
                details['environment_state'] = 'complete'
            except Exception as e:
                failed += 1
                errors.append(f"environment_state: {e}")

            # Test 6: VPN detection
            self.logger.verbose("Test 6: VPN detection")
            try:
                is_vpn = monitor.is_vpn_active()
                assert isinstance(is_vpn, bool)
                passed += 1
                details['vpn_active'] = is_vpn
            except Exception as e:
                failed += 1
                errors.append(f"vpn_detection: {e}")

            # Test 7: Airgap detection
            self.logger.verbose("Test 7: Airgap detection")
            try:
                is_airgapped = monitor.is_airgapped()
                assert isinstance(is_airgapped, bool)
                passed += 1
                details['is_airgapped'] = is_airgapped
            except Exception as e:
                failed += 1
                errors.append(f"airgap_detection: {e}")

            # Test 8: USB device detection
            self.logger.verbose("Test 8: USB device detection")
            try:
                usb_devices = monitor.get_usb_devices()
                assert isinstance(usb_devices, (list, tuple))
                passed += 1
                details['usb_device_count'] = len(usb_devices)
            except AttributeError:
                skipped += 1
                details['usb_detection'] = 'not available'
            except Exception as e:
                failed += 1
                errors.append(f"usb_detection: {e}")

        except ImportError as e:
            errors.append(f"Import error: {e}")

        duration = (time.perf_counter() - start) * 1000
        self.logger.info(f"State Monitor: {passed} passed, {failed} failed, {skipped} skipped")

        return PipelineTestResult(
            name='state_monitor',
            passed=passed,
            failed=failed,
            skipped=skipped,
            errors=errors,
            duration_ms=duration,
            details=details
        )

    def test_policy_engine_pipeline(self) -> PipelineTestResult:
        """Test policy engine pipeline comprehensively."""
        self.logger.info("=" * 50)
        self.logger.info("Testing Policy Engine Pipeline")
        self.logger.info("=" * 50)

        start = time.perf_counter()
        passed = 0
        failed = 0
        skipped = 0
        errors = []
        details = {}

        try:
            from daemon.policy_engine import (
                PolicyEngine, BoundaryMode, PolicyRequest,
                PolicyDecision, MemoryClass, Operator
            )

            # Test 1: All mode instantiation
            self.logger.verbose("Test 1: All mode instantiation")
            try:
                for mode in BoundaryMode:
                    engine = PolicyEngine(initial_mode=mode)
                    assert engine.current_mode == mode
                passed += 1
                details['all_modes'] = 'passed'
            except Exception as e:
                failed += 1
                errors.append(f"mode_instantiation: {e}")

            # Test 2: Mode transitions
            self.logger.verbose("Test 2: Mode transitions")
            try:
                engine = PolicyEngine(initial_mode=BoundaryMode.OPEN)
                transitions = [
                    BoundaryMode.RESTRICTED,
                    BoundaryMode.TRUSTED,
                    BoundaryMode.AIRGAP,
                    BoundaryMode.OPEN
                ]
                for target_mode in transitions:
                    engine.set_mode(target_mode)
                    assert engine.current_mode == target_mode
                passed += 1
                details['transitions'] = 'all_successful'
            except Exception as e:
                failed += 1
                errors.append(f"transitions: {e}")

            # Test 3: Memory recall policy for each class
            self.logger.verbose("Test 3: Memory recall policies")
            try:
                engine = PolicyEngine(initial_mode=BoundaryMode.TRUSTED)
                for mem_class in MemoryClass:
                    request = PolicyRequest(
                        request_type='recall',
                        memory_class=mem_class,
                        requires_network=False
                    )
                    decision = engine.evaluate(request)
                    assert isinstance(decision, PolicyDecision)
                passed += 1
                details['recall_policies'] = 'all_evaluated'
            except Exception as e:
                failed += 1
                errors.append(f"recall_policy: {e}")

            # Test 4: Tool request policies
            self.logger.verbose("Test 4: Tool request policies")
            try:
                engine = PolicyEngine(initial_mode=BoundaryMode.OPEN)
                tools = ['file_read', 'file_write', 'http_request', 'shell_execute']
                results = {}
                for tool in tools:
                    request = PolicyRequest(
                        request_type='tool',
                        tool_name=tool,
                        requires_network='http' in tool or 'network' in tool,
                        requires_filesystem='file' in tool or 'shell' in tool
                    )
                    decision = engine.evaluate(request)
                    results[tool] = decision.allowed
                passed += 1
                details['tool_policies'] = results
            except Exception as e:
                failed += 1
                errors.append(f"tool_policy: {e}")

            # Test 5: AIRGAP mode blocks network
            self.logger.verbose("Test 5: AIRGAP network blocking")
            try:
                engine = PolicyEngine(initial_mode=BoundaryMode.AIRGAP)
                request = PolicyRequest(
                    request_type='tool',
                    tool_name='http_request',
                    requires_network=True
                )
                decision = engine.evaluate(request)
                assert decision.allowed is False
                passed += 1
                details['airgap_network_block'] = 'verified'
            except Exception as e:
                failed += 1
                errors.append(f"airgap_block: {e}")

            # Test 6: LOCKDOWN mode
            self.logger.verbose("Test 6: LOCKDOWN mode restrictions")
            try:
                engine = PolicyEngine(initial_mode=BoundaryMode.LOCKDOWN)
                blocked_count = 0
                for mem_class in [MemoryClass.PUBLIC, MemoryClass.CONFIDENTIAL]:
                    request = PolicyRequest(
                        request_type='recall',
                        memory_class=mem_class,
                        requires_network=False
                    )
                    decision = engine.evaluate(request)
                    if not decision.allowed:
                        blocked_count += 1
                assert blocked_count > 0
                passed += 1
                details['lockdown_blocks'] = blocked_count
            except Exception as e:
                failed += 1
                errors.append(f"lockdown: {e}")

            # Test 7: Callback registration
            self.logger.verbose("Test 7: Mode change callbacks")
            try:
                callback_data = {'called': False, 'old': None, 'new': None}

                def callback(old_mode, new_mode):
                    callback_data['called'] = True
                    callback_data['old'] = old_mode
                    callback_data['new'] = new_mode

                engine = PolicyEngine(initial_mode=BoundaryMode.OPEN)
                engine.register_mode_callback(callback)
                engine.set_mode(BoundaryMode.RESTRICTED)

                assert callback_data['called']
                assert callback_data['old'] == BoundaryMode.OPEN
                assert callback_data['new'] == BoundaryMode.RESTRICTED
                passed += 1
                details['callbacks'] = 'verified'
            except Exception as e:
                failed += 1
                errors.append(f"callbacks: {e}")

        except ImportError as e:
            errors.append(f"Import error: {e}")

        duration = (time.perf_counter() - start) * 1000
        self.logger.info(f"Policy Engine: {passed} passed, {failed} failed, {skipped} skipped")

        return PipelineTestResult(
            name='policy_engine',
            passed=passed,
            failed=failed,
            skipped=skipped,
            errors=errors,
            duration_ms=duration,
            details=details
        )

    def test_tripwire_pipeline(self) -> PipelineTestResult:
        """Test tripwire system pipeline comprehensively."""
        self.logger.info("=" * 50)
        self.logger.info("Testing Tripwire Pipeline")
        self.logger.info("=" * 50)

        start = time.perf_counter()
        passed = 0
        failed = 0
        skipped = 0
        errors = []
        details = {}

        try:
            from daemon.tripwires import (
                TripwireSystem, ViolationType, TripwireViolation
            )

            # Test 1: Instantiation
            self.logger.verbose("Test 1: TripwireSystem instantiation")
            try:
                tripwire = TripwireSystem()
                passed += 1
            except Exception as e:
                failed += 1
                errors.append(f"instantiation: {e}")

            # Test 2: Violation types exist
            self.logger.verbose("Test 2: Violation types")
            try:
                expected = [
                    'NETWORK_IN_AIRGAP', 'USB_IN_COLDROOM',
                    'UNAUTHORIZED_RECALL', 'DAEMON_TAMPERING',
                    'MODE_INCOMPATIBLE'
                ]
                for vtype in expected:
                    assert hasattr(ViolationType, vtype), f"Missing: {vtype}"
                passed += 1
                details['violation_types'] = len(list(ViolationType))
            except Exception as e:
                failed += 1
                errors.append(f"violation_types: {e}")

            # Test 3: Get violations
            self.logger.verbose("Test 3: Get violations list")
            try:
                tripwire = TripwireSystem()
                violations = tripwire.get_violations()
                assert isinstance(violations, list)
                passed += 1
            except Exception as e:
                failed += 1
                errors.append(f"get_violations: {e}")

            # Test 4: Auto-lockdown configuration
            self.logger.verbose("Test 4: Auto-lockdown config")
            try:
                tripwire = TripwireSystem(auto_lockdown=True)
                assert tripwire.auto_lockdown_enabled is True
                tripwire2 = TripwireSystem(auto_lockdown=False)
                assert tripwire2.auto_lockdown_enabled is False
                passed += 1
            except Exception as e:
                failed += 1
                errors.append(f"auto_lockdown: {e}")

            # Test 5: Violation history
            self.logger.verbose("Test 5: Violation history")
            try:
                tripwire = TripwireSystem()
                history = tripwire.get_violation_history()
                assert isinstance(history, list)
                passed += 1
            except Exception as e:
                failed += 1
                errors.append(f"history: {e}")

        except ImportError as e:
            errors.append(f"Import error: {e}")

        duration = (time.perf_counter() - start) * 1000
        self.logger.info(f"Tripwires: {passed} passed, {failed} failed, {skipped} skipped")

        return PipelineTestResult(
            name='tripwires',
            passed=passed,
            failed=failed,
            skipped=skipped,
            errors=errors,
            duration_ms=duration,
            details=details
        )

    def test_event_logger_pipeline(self) -> PipelineTestResult:
        """Test event logger pipeline comprehensively."""
        self.logger.info("=" * 50)
        self.logger.info("Testing Event Logger Pipeline")
        self.logger.info("=" * 50)

        start = time.perf_counter()
        passed = 0
        failed = 0
        skipped = 0
        errors = []
        details = {}

        log_path = self.temp_dir / "test_events.log"

        try:
            from daemon.event_logger import EventLogger, EventType

            # Test 1: Instantiation
            self.logger.verbose("Test 1: EventLogger instantiation")
            try:
                logger_obj = EventLogger(str(log_path), secure_permissions=False)
                passed += 1
            except Exception as e:
                failed += 1
                errors.append(f"instantiation: {e}")
                return PipelineTestResult(
                    name='event_logger', passed=0, failed=1, skipped=0,
                    errors=errors, duration_ms=(time.perf_counter() - start) * 1000,
                    details={}
                )

            # Test 2: Log all event types
            self.logger.verbose("Test 2: Log all event types")
            try:
                for event_type in EventType:
                    event_id = logger_obj.log_event(
                        event_type,
                        f"Test event: {event_type.name}",
                        {"test": True}
                    )
                    assert event_id is not None
                passed += 1
                details['event_types_logged'] = len(list(EventType))
            except Exception as e:
                failed += 1
                errors.append(f"log_events: {e}")

            # Test 3: Retrieve recent events
            self.logger.verbose("Test 3: Retrieve recent events")
            try:
                events = logger_obj.get_recent_events(limit=100)
                assert len(events) > 0
                passed += 1
                details['events_retrieved'] = len(events)
            except Exception as e:
                failed += 1
                errors.append(f"get_events: {e}")

            # Test 4: Hash chain verification
            self.logger.verbose("Test 4: Hash chain verification")
            try:
                is_valid = logger_obj.verify_chain()
                assert is_valid is True
                passed += 1
                details['chain_valid'] = True
            except Exception as e:
                failed += 1
                errors.append(f"verify_chain: {e}")

            # Test 5: Filter by type
            self.logger.verbose("Test 5: Filter by type")
            try:
                mode_events = logger_obj.get_events_by_type(EventType.MODE_CHANGE)
                info_events = logger_obj.get_events_by_type(EventType.INFO)
                passed += 1
                details['mode_change_events'] = len(mode_events)
                details['info_events'] = len(info_events)
            except Exception as e:
                failed += 1
                errors.append(f"filter_events: {e}")

            # Test 6: Export log
            self.logger.verbose("Test 6: Export log")
            try:
                export_data = logger_obj.export_log()
                assert export_data is not None
                passed += 1
            except Exception as e:
                failed += 1
                errors.append(f"export_log: {e}")

            # Test 7: Thread safety
            self.logger.verbose("Test 7: Thread safety")
            try:
                def log_events(n):
                    for i in range(n):
                        logger_obj.log_event(EventType.INFO, f"Thread event {i}", {})

                threads = [threading.Thread(target=log_events, args=(10,)) for _ in range(5)]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join(timeout=5)

                # Verify chain still valid after concurrent writes
                assert logger_obj.verify_chain() is True
                passed += 1
                details['thread_safety'] = 'verified'
            except Exception as e:
                failed += 1
                errors.append(f"thread_safety: {e}")

        except ImportError as e:
            errors.append(f"Import error: {e}")

        duration = (time.perf_counter() - start) * 1000
        self.logger.info(f"Event Logger: {passed} passed, {failed} failed, {skipped} skipped")

        return PipelineTestResult(
            name='event_logger',
            passed=passed,
            failed=failed,
            skipped=skipped,
            errors=errors,
            duration_ms=duration,
            details=details
        )

    def test_security_pipeline(self) -> PipelineTestResult:
        """Test security modules pipeline comprehensively."""
        self.logger.info("=" * 50)
        self.logger.info("Testing Security Pipeline")
        self.logger.info("=" * 50)

        start = time.perf_counter()
        passed = 0
        failed = 0
        skipped = 0
        errors = []
        details = {}

        security_modules = [
            ('dns_security', 'daemon.security.dns_security', 'DNSSecurityMonitor'),
            ('arp_security', 'daemon.security.arp_security', 'ARPSecurityMonitor'),
            ('prompt_injection', 'daemon.security.prompt_injection', 'PromptInjectionDetector'),
            ('file_integrity', 'daemon.security.file_integrity', 'FileIntegrityMonitor'),
            ('clock_monitor', 'daemon.security.clock_monitor', 'ClockMonitor'),
            ('threat_intel', 'daemon.security.threat_intel', 'ThreatIntelligence'),
            ('response_guardrails', 'daemon.security.response_guardrails', 'ResponseGuardrails'),
            ('daemon_integrity', 'daemon.security.daemon_integrity', 'DaemonIntegrityProtector'),
        ]

        for module_name, module_path, class_name in security_modules:
            self.logger.verbose(f"Testing {module_name}")
            try:
                module = __import__(module_path, fromlist=[class_name])
                cls = getattr(module, class_name)
                instance = cls()
                passed += 1
                details[module_name] = 'loaded'
            except ImportError:
                skipped += 1
                details[module_name] = 'not available'
            except PermissionError:
                skipped += 1
                details[module_name] = 'needs root'
            except Exception as e:
                failed += 1
                errors.append(f"{module_name}: {e}")
                details[module_name] = f'error: {e}'

        duration = (time.perf_counter() - start) * 1000
        self.logger.info(f"Security: {passed} passed, {failed} failed, {skipped} skipped")

        return PipelineTestResult(
            name='security',
            passed=passed,
            failed=failed,
            skipped=skipped,
            errors=errors,
            duration_ms=duration,
            details=details
        )

    def test_enforcement_pipeline(self) -> PipelineTestResult:
        """Test enforcement modules pipeline comprehensively."""
        self.logger.info("=" * 50)
        self.logger.info("Testing Enforcement Pipeline")
        self.logger.info("=" * 50)

        start = time.perf_counter()
        passed = 0
        failed = 0
        skipped = 0
        errors = []
        details = {}

        enforcement_modules = [
            ('network_enforcer', 'daemon.enforcement', 'NetworkEnforcer'),
            ('usb_enforcer', 'daemon.enforcement', 'USBEnforcer'),
            ('process_enforcer', 'daemon.enforcement', 'ProcessEnforcer'),
            ('protection_persistence', 'daemon.enforcement', 'ProtectionPersistenceManager'),
        ]

        for module_name, module_path, class_name in enforcement_modules:
            self.logger.verbose(f"Testing {module_name}")
            try:
                module = __import__(module_path, fromlist=[class_name])
                cls = getattr(module, class_name)

                if class_name == 'ProtectionPersistenceManager':
                    instance = cls(state_dir=str(self.temp_dir / f"{module_name}_state"))
                else:
                    instance = cls()

                passed += 1
                details[module_name] = 'loaded'
            except ImportError:
                skipped += 1
                details[module_name] = 'not available'
            except PermissionError:
                skipped += 1
                details[module_name] = 'needs root'
            except Exception as e:
                failed += 1
                errors.append(f"{module_name}: {e}")
                details[module_name] = f'error: {e}'

        duration = (time.perf_counter() - start) * 1000
        self.logger.info(f"Enforcement: {passed} passed, {failed} failed, {skipped} skipped")

        return PipelineTestResult(
            name='enforcement',
            passed=passed,
            failed=failed,
            skipped=skipped,
            errors=errors,
            duration_ms=duration,
            details=details
        )

    def test_sandbox_pipeline(self) -> PipelineTestResult:
        """Test sandbox modules pipeline comprehensively."""
        self.logger.info("=" * 50)
        self.logger.info("Testing Sandbox Pipeline")
        self.logger.info("=" * 50)

        start = time.perf_counter()
        passed = 0
        failed = 0
        skipped = 0
        errors = []
        details = {}

        sandbox_modules = [
            ('sandbox_manager', 'daemon.sandbox', 'SandboxManager'),
            ('seccomp_filter', 'daemon.sandbox.seccomp_filter', 'SeccompFilter'),
            ('namespace', 'daemon.sandbox.namespace', 'NamespaceManager'),
            ('cgroups', 'daemon.sandbox.cgroups', 'CGroupManager'),
            ('profile_config', 'daemon.sandbox.profile_config', 'SandboxProfile'),
        ]

        for module_name, module_path, class_name in sandbox_modules:
            self.logger.verbose(f"Testing {module_name}")
            try:
                module = __import__(module_path, fromlist=[class_name])
                cls = getattr(module, class_name)

                if class_name == 'SandboxProfile':
                    instance = cls(name="test")
                else:
                    instance = cls()

                passed += 1
                details[module_name] = 'loaded'
            except ImportError:
                skipped += 1
                details[module_name] = 'not available'
            except PermissionError:
                skipped += 1
                details[module_name] = 'needs root'
            except Exception as e:
                failed += 1
                errors.append(f"{module_name}: {e}")
                details[module_name] = f'error: {e}'

        duration = (time.perf_counter() - start) * 1000
        self.logger.info(f"Sandbox: {passed} passed, {failed} failed, {skipped} skipped")

        return PipelineTestResult(
            name='sandbox',
            passed=passed,
            failed=failed,
            skipped=skipped,
            errors=errors,
            duration_ms=duration,
            details=details
        )

    def test_auth_pipeline(self) -> PipelineTestResult:
        """Test authentication/ceremony pipeline comprehensively."""
        self.logger.info("=" * 50)
        self.logger.info("Testing Auth Pipeline")
        self.logger.info("=" * 50)

        start = time.perf_counter()
        passed = 0
        failed = 0
        skipped = 0
        errors = []
        details = {}

        auth_modules = [
            ('api_auth', 'daemon.auth.api_auth', 'APIAuthenticator'),
            ('advanced_ceremony', 'daemon.auth.advanced_ceremony', 'AdvancedCeremonyManager'),
            ('biometric_verifier', 'daemon.auth.biometric_verifier', 'BiometricVerifier'),
            ('persistent_rate_limiter', 'daemon.auth.persistent_rate_limiter', 'PersistentRateLimiter'),
            ('secure_token_storage', 'daemon.auth.secure_token_storage', 'SecureTokenStorage'),
        ]

        for module_name, module_path, class_name in auth_modules:
            self.logger.verbose(f"Testing {module_name}")
            try:
                module = __import__(module_path, fromlist=[class_name])
                cls = getattr(module, class_name)

                if class_name == 'PersistentRateLimiter':
                    instance = cls(storage_path=str(self.temp_dir / f"{module_name}.db"))
                elif class_name == 'SecureTokenStorage':
                    instance = cls(storage_path=str(self.temp_dir / f"{module_name}.enc"))
                else:
                    instance = cls()

                passed += 1
                details[module_name] = 'loaded'
            except ImportError:
                skipped += 1
                details[module_name] = 'not available'
            except Exception as e:
                failed += 1
                errors.append(f"{module_name}: {e}")
                details[module_name] = f'error: {e}'

        duration = (time.perf_counter() - start) * 1000
        self.logger.info(f"Auth: {passed} passed, {failed} failed, {skipped} skipped")

        return PipelineTestResult(
            name='auth',
            passed=passed,
            failed=failed,
            skipped=skipped,
            errors=errors,
            duration_ms=duration,
            details=details
        )

    def test_health_pipeline(self) -> PipelineTestResult:
        """Test health monitoring pipeline comprehensively."""
        self.logger.info("=" * 50)
        self.logger.info("Testing Health Pipeline")
        self.logger.info("=" * 50)

        start = time.perf_counter()
        passed = 0
        failed = 0
        skipped = 0
        errors = []
        details = {}

        try:
            from daemon.health_monitor import HealthMonitor, HealthStatus

            # Test 1: Instantiation
            self.logger.verbose("Test 1: HealthMonitor instantiation")
            try:
                monitor = HealthMonitor()
                passed += 1
            except Exception as e:
                failed += 1
                errors.append(f"instantiation: {e}")
                return PipelineTestResult(
                    name='health', passed=0, failed=1, skipped=0,
                    errors=errors, duration_ms=(time.perf_counter() - start) * 1000,
                    details={}
                )

            # Test 2: Status check
            self.logger.verbose("Test 2: Health status check")
            try:
                status = monitor.get_status()
                assert status in (HealthStatus.HEALTHY, HealthStatus.DEGRADED,
                                  HealthStatus.UNHEALTHY, HealthStatus.UNKNOWN)
                passed += 1
                details['status'] = str(status)
            except Exception as e:
                failed += 1
                errors.append(f"status: {e}")

            # Test 3: Component registration
            self.logger.verbose("Test 3: Component registration")
            try:
                monitor.register_component("test_component_1")
                monitor.register_component("test_component_2")
                components = monitor.get_components()
                assert "test_component_1" in components
                assert "test_component_2" in components
                passed += 1
                details['components'] = list(components)
            except Exception as e:
                failed += 1
                errors.append(f"registration: {e}")

            # Test 4: Heartbeat
            self.logger.verbose("Test 4: Heartbeat mechanism")
            try:
                monitor.heartbeat("test_component_1")
                passed += 1
            except Exception as e:
                failed += 1
                errors.append(f"heartbeat: {e}")

            # Test 5: Health snapshot
            self.logger.verbose("Test 5: Health snapshot")
            try:
                snapshot = monitor.get_snapshot()
                assert snapshot is not None
                passed += 1
            except Exception as e:
                failed += 1
                errors.append(f"snapshot: {e}")

        except ImportError as e:
            errors.append(f"Import error: {e}")

        duration = (time.perf_counter() - start) * 1000
        self.logger.info(f"Health: {passed} passed, {failed} failed, {skipped} skipped")

        return PipelineTestResult(
            name='health',
            passed=passed,
            failed=failed,
            skipped=skipped,
            errors=errors,
            duration_ms=duration,
            details=details
        )

    def test_integration_pipeline(self) -> PipelineTestResult:
        """Test integration modules pipeline comprehensively."""
        self.logger.info("=" * 50)
        self.logger.info("Testing Integration Pipeline")
        self.logger.info("=" * 50)

        start = time.perf_counter()
        passed = 0
        failed = 0
        skipped = 0
        errors = []
        details = {}

        integrations = [
            ('memory_vault', 'integrations.memory_vault', 'MemoryVaultIntegration'),
            ('agent_os', 'integrations.agent_os', 'AgentOSIntegration'),
            ('siem', 'daemon.security.siem_integration', 'SIEMIntegration'),
        ]

        for integration_name, module_path, class_name in integrations:
            self.logger.verbose(f"Testing {integration_name}")
            try:
                module = __import__(module_path, fromlist=[class_name])
                cls = getattr(module, class_name)
                instance = cls()
                passed += 1
                details[integration_name] = 'loaded'
            except ImportError:
                skipped += 1
                details[integration_name] = 'not available'
            except Exception as e:
                failed += 1
                errors.append(f"{integration_name}: {e}")
                details[integration_name] = f'error: {e}'

        duration = (time.perf_counter() - start) * 1000
        self.logger.info(f"Integrations: {passed} passed, {failed} failed, {skipped} skipped")

        return PipelineTestResult(
            name='integration',
            passed=passed,
            failed=failed,
            skipped=skipped,
            errors=errors,
            duration_ms=duration,
            details=details
        )

    def test_full_daemon_lifecycle(self) -> PipelineTestResult:
        """Test full daemon lifecycle end-to-end."""
        self.logger.info("=" * 50)
        self.logger.info("Testing Full Daemon Lifecycle")
        self.logger.info("=" * 50)

        start = time.perf_counter()
        passed = 0
        failed = 0
        skipped = 0
        errors = []
        details = {}

        try:
            from daemon.boundary_daemon import BoundaryDaemon, BoundaryMode

            log_dir = str(self.temp_dir / "daemon_logs")

            # Test 1: Create daemon
            self.logger.verbose("Test 1: Create daemon instance")
            try:
                daemon = BoundaryDaemon(
                    log_dir=log_dir,
                    initial_mode=BoundaryMode.OPEN,
                    skip_integrity_check=True
                )
                passed += 1
                details['creation'] = 'success'
            except Exception as e:
                failed += 1
                errors.append(f"creation: {e}")
                return PipelineTestResult(
                    name='full_lifecycle', passed=0, failed=1, skipped=0,
                    errors=errors, duration_ms=(time.perf_counter() - start) * 1000,
                    details={}
                )

            # Test 2: Check mode
            self.logger.verbose("Test 2: Verify initial mode")
            try:
                assert daemon.policy_engine.current_mode == BoundaryMode.OPEN
                passed += 1
                details['initial_mode'] = 'OPEN'
            except Exception as e:
                failed += 1
                errors.append(f"mode_check: {e}")

            # Test 3: State monitor available
            self.logger.verbose("Test 3: State monitor available")
            try:
                assert daemon.state_monitor is not None
                passed += 1
            except Exception as e:
                failed += 1
                errors.append(f"state_monitor: {e}")

            # Test 4: Event logger available
            self.logger.verbose("Test 4: Event logger available")
            try:
                assert daemon.event_logger is not None
                passed += 1
            except Exception as e:
                failed += 1
                errors.append(f"event_logger: {e}")

            # Test 5: Tripwire system available
            self.logger.verbose("Test 5: Tripwire system available")
            try:
                assert daemon.tripwire_system is not None
                passed += 1
            except Exception as e:
                failed += 1
                errors.append(f"tripwire: {e}")

        except ImportError as e:
            errors.append(f"Import error: {e}")

        duration = (time.perf_counter() - start) * 1000
        self.logger.info(f"Full Lifecycle: {passed} passed, {failed} failed, {skipped} skipped")

        return PipelineTestResult(
            name='full_lifecycle',
            passed=passed,
            failed=failed,
            skipped=skipped,
            errors=errors,
            duration_ms=duration,
            details=details
        )


def run_comprehensive_tests(verbose: bool = False, trace: bool = False) -> List[PipelineTestResult]:
    """Run all comprehensive pipeline tests."""
    setup_logging(verbose=verbose, trace=trace)
    tests = ComprehensivePipelineTests(verbose=verbose, trace=trace)
    return tests.run_all()


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description="Comprehensive Pipeline Tests")
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--trace', '-t', action='store_true', help='Trace output')

    args = parser.parse_args()

    results = run_comprehensive_tests(verbose=args.verbose, trace=args.trace)

    # Summary
    total_passed = sum(r.passed for r in results)
    total_failed = sum(r.failed for r in results)
    total_skipped = sum(r.skipped for r in results)

    print("\n" + "=" * 60)
    print("COMPREHENSIVE TEST SUMMARY")
    print("=" * 60)
    print(f"Pipelines: {len(results)}")
    print(f"Total: {total_passed + total_failed + total_skipped}")
    print(f"  Passed:  {total_passed}")
    print(f"  Failed:  {total_failed}")
    print(f"  Skipped: {total_skipped}")

    if total_failed > 0:
        print("\nFailed tests:")
        for r in results:
            if r.failed > 0:
                print(f"  {r.name}: {r.errors}")

    sys.exit(1 if total_failed > 0 else 0)
