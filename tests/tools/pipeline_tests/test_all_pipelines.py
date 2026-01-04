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
    setup_logging, get_logger,
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
                HardwareTrust, EnvironmentState, MonitoringConfig
            )

            # Test 1: Instantiation
            self.logger.verbose("Test 1: StateMonitor instantiation")
            try:
                monitor = StateMonitor()
                passed += 1
                details['instantiation'] = 'passed'
            except Exception as e:
                failed += 1
                errors.append(f"instantiation: {e}")
                details['instantiation'] = f'failed: {e}'

            # Test 2: Current state retrieval
            self.logger.verbose("Test 2: Current state retrieval")
            try:
                state = monitor.get_current_state()
                # Can be None if not yet polled, or EnvironmentState
                assert state is None or isinstance(state, EnvironmentState)
                passed += 1
                details['current_state'] = 'available' if state else 'none'
            except Exception as e:
                failed += 1
                errors.append(f"current_state: {e}")

            # Test 3: Monitoring config
            self.logger.verbose("Test 3: Monitoring config")
            try:
                config = monitor.get_monitoring_config()
                assert isinstance(config, MonitoringConfig)
                passed += 1
                details['monitoring_config'] = 'available'
            except Exception as e:
                failed += 1
                errors.append(f"monitoring_config: {e}")

            # Test 4: Network change detection
            self.logger.verbose("Test 4: Network change detection")
            try:
                changed = monitor.get_network_change_detected()
                assert isinstance(changed, bool)
                passed += 1
                details['network_change'] = changed
            except Exception as e:
                failed += 1
                errors.append(f"network_change: {e}")

            # Test 5: USB change detection
            self.logger.verbose("Test 5: USB change detection")
            try:
                inserted, removed = monitor.get_usb_changes()
                assert isinstance(inserted, set) and isinstance(removed, set)
                passed += 1
                details['usb_changes'] = f'{len(inserted)} inserted, {len(removed)} removed'
            except Exception as e:
                failed += 1
                errors.append(f"usb_changes: {e}")

            # Test 6: Enum types exist
            self.logger.verbose("Test 6: Enum types verification")
            try:
                assert NetworkState.ONLINE is not None
                assert NetworkState.OFFLINE is not None
                assert NetworkType.ETHERNET is not None
                assert NetworkType.WIFI is not None
                assert HardwareTrust.LOW is not None
                assert HardwareTrust.MEDIUM is not None
                assert HardwareTrust.HIGH is not None
                passed += 1
                details['enum_types'] = 'all defined'
            except Exception as e:
                failed += 1
                errors.append(f"enum_types: {e}")

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
            from daemon.state_monitor import EnvironmentState, NetworkState, HardwareTrust
            from unittest.mock import MagicMock

            # Helper to create mock environment state
            def make_env_state():
                mock_env = MagicMock(spec=EnvironmentState)
                mock_env.network = NetworkState.ONLINE
                mock_env.hardware_trust = HardwareTrust.MEDIUM
                mock_env.vpn_active = False
                mock_env.usb_devices = set()
                mock_env.external_model_endpoints = []
                mock_env.has_internet = True
                return mock_env

            # Test 1: All mode instantiation
            self.logger.verbose("Test 1: All mode instantiation")
            try:
                for mode in BoundaryMode:
                    engine = PolicyEngine(initial_mode=mode)
                    assert engine.get_current_mode() == mode
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
                    BoundaryMode.OPEN
                ]
                for target_mode in transitions:
                    success, msg = engine.transition_mode(target_mode, Operator.HUMAN)
                    assert success, f"Transition to {target_mode} failed: {msg}"
                    assert engine.get_current_mode() == target_mode
                passed += 1
                details['transitions'] = 'all_successful'
            except Exception as e:
                failed += 1
                errors.append(f"transitions: {e}")

            # Test 3: Memory recall policy for each class
            self.logger.verbose("Test 3: Memory recall policies")
            try:
                engine = PolicyEngine(initial_mode=BoundaryMode.TRUSTED)
                env = make_env_state()
                for mem_class in MemoryClass:
                    request = PolicyRequest(
                        request_type='recall',
                        memory_class=mem_class,
                    )
                    decision = engine.evaluate_policy(request, env)
                    assert isinstance(decision, PolicyDecision)
                passed += 1
                details['recall_policies'] = 'all_evaluated'
            except Exception as e:
                failed += 1
                errors.append(f"recall_policy: {e}")

            # Test 4: Get current state
            self.logger.verbose("Test 4: Get current state")
            try:
                engine = PolicyEngine(initial_mode=BoundaryMode.TRUSTED)
                state = engine.get_current_state()
                assert state is not None and hasattr(state, 'mode')
                passed += 1
                details['current_state'] = 'available'
            except Exception as e:
                failed += 1
                errors.append(f"current_state: {e}")

            # Test 5: LOCKDOWN mode blocks operations
            self.logger.verbose("Test 5: LOCKDOWN mode blocking")
            try:
                engine = PolicyEngine(initial_mode=BoundaryMode.LOCKDOWN)
                env = make_env_state()
                request = PolicyRequest(
                    request_type='recall',
                    memory_class=MemoryClass.PUBLIC,
                )
                decision = engine.evaluate_policy(request, env)
                assert decision == PolicyDecision.DENY
                passed += 1
                details['lockdown_blocking'] = 'verified'
            except Exception as e:
                failed += 1
                errors.append(f"lockdown: {e}")

            # Test 6: LOCKDOWN exit requires human
            self.logger.verbose("Test 6: LOCKDOWN exit requires human")
            try:
                engine = PolicyEngine(initial_mode=BoundaryMode.LOCKDOWN)
                success, msg = engine.transition_mode(BoundaryMode.OPEN, Operator.SYSTEM)
                assert not success  # Should fail without human
                passed += 1
                details['lockdown_exit'] = 'human required'
            except Exception as e:
                failed += 1
                errors.append(f"lockdown_exit: {e}")

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
                TripwireSystem, ViolationType, TripwireViolation, LockdownManager
            )
            from collections import deque

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

            # Test 3: Get violations (can be list or deque)
            self.logger.verbose("Test 3: Get violations")
            try:
                tripwire = TripwireSystem()
                violations = tripwire.get_violations()
                assert isinstance(violations, (list, deque))
                passed += 1
                details['violations'] = len(violations)
            except Exception as e:
                failed += 1
                errors.append(f"get_violations: {e}")

            # Test 4: Is enabled check
            self.logger.verbose("Test 4: Is enabled check")
            try:
                tripwire = TripwireSystem()
                enabled = tripwire.is_enabled()
                assert enabled is True
                passed += 1
                details['is_enabled'] = enabled
            except Exception as e:
                failed += 1
                errors.append(f"is_enabled: {e}")

            # Test 5: Violation count
            self.logger.verbose("Test 5: Violation count")
            try:
                tripwire = TripwireSystem()
                count = tripwire.get_violation_count()
                assert isinstance(count, int) and count >= 0
                passed += 1
                details['violation_count'] = count
            except Exception as e:
                failed += 1
                errors.append(f"violation_count: {e}")

            # Test 6: LockdownManager
            self.logger.verbose("Test 6: LockdownManager")
            try:
                manager = LockdownManager()
                assert manager is not None
                assert hasattr(manager, 'trigger_lockdown')
                passed += 1
                details['lockdown_manager'] = 'available'
            except Exception as e:
                failed += 1
                errors.append(f"lockdown_manager: {e}")

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

            # Test 3: Retrieve recent events (parameter is 'count', not 'limit')
            self.logger.verbose("Test 3: Retrieve recent events")
            try:
                events = logger_obj.get_recent_events(count=100)
                assert len(events) > 0
                passed += 1
                details['events_retrieved'] = len(events)
            except Exception as e:
                failed += 1
                errors.append(f"get_events: {e}")

            # Test 4: Hash chain verification
            self.logger.verbose("Test 4: Hash chain verification")
            try:
                result = logger_obj.verify_chain()
                # Returns tuple (is_valid, error_message) or just bool
                if isinstance(result, tuple):
                    is_valid = result[0]
                else:
                    is_valid = result
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

            # Test 6: Export log (requires output_path)
            self.logger.verbose("Test 6: Export log")
            try:
                export_path = str(self.temp_dir / "export.log")
                result = logger_obj.export_log(export_path)
                assert result is True or os.path.exists(export_path)
                passed += 1
                details['export'] = 'success'
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
                result = logger_obj.verify_chain()
                if isinstance(result, tuple):
                    is_valid = result[0]
                else:
                    is_valid = result
                assert is_valid is True
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
            ('threat_intel', 'daemon.security.threat_intel', 'ThreatIntelMonitor'),
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
            ('sandbox_manager', 'daemon.sandbox', 'SandboxManager', {}),
            ('seccomp_filter', 'daemon.sandbox.seccomp_filter', 'SeccompFilter', {}),
            ('namespace', 'daemon.sandbox.namespace', 'NamespaceManager', {}),
            ('cgroups', 'daemon.sandbox.cgroups', 'CgroupManager', {}),
            ('profile_config', 'daemon.sandbox.profile_config', 'SandboxProfileConfig', {'name': 'test'}),
        ]

        for module_name, module_path, class_name, kwargs in sandbox_modules:
            self.logger.verbose(f"Testing {module_name}")
            try:
                module = __import__(module_path, fromlist=[class_name])
                cls = getattr(module, class_name)
                instance = cls(**kwargs)

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

        from unittest.mock import MagicMock

        auth_modules = [
            ('api_auth', 'daemon.auth.api_auth', 'TokenManager', {}),
            ('advanced_ceremony', 'daemon.auth.advanced_ceremony', 'AdvancedCeremonyManager', {'daemon': MagicMock()}),
            ('biometric_verifier', 'daemon.auth.biometric_verifier', 'BiometricVerifier', {}),
            ('persistent_rate_limiter', 'daemon.auth.persistent_rate_limiter', 'PersistentRateLimiter',
             {'state_file': str(self.temp_dir / "rate_limit.json")}),
            ('secure_token_storage', 'daemon.auth.secure_token_storage', 'SecureTokenStorage',
             {'key_file': str(self.temp_dir / "tokens.key")}),
        ]

        for module_name, module_path, class_name, kwargs in auth_modules:
            self.logger.verbose(f"Testing {module_name}")
            try:
                module = __import__(module_path, fromlist=[class_name])
                cls = getattr(module, class_name)
                instance = cls(**kwargs)
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
            from daemon.health_monitor import (
                HealthMonitor, HealthStatus, HealthSnapshot,
                ComponentStatus, ComponentHealth
            )
            from unittest.mock import MagicMock

            # Test 1: HealthStatus enum
            self.logger.verbose("Test 1: HealthStatus enum")
            try:
                assert HealthStatus.HEALTHY is not None
                assert HealthStatus.DEGRADED is not None
                assert HealthStatus.UNHEALTHY is not None
                assert HealthStatus.UNKNOWN is not None
                passed += 1
                details['health_status_enum'] = 'defined'
            except Exception as e:
                failed += 1
                errors.append(f"health_status_enum: {e}")

            # Test 2: ComponentStatus enum
            self.logger.verbose("Test 2: ComponentStatus enum")
            try:
                assert ComponentStatus.OK is not None
                assert ComponentStatus.WARNING is not None
                assert ComponentStatus.ERROR is not None
                passed += 1
                details['component_status_enum'] = 'defined'
            except Exception as e:
                failed += 1
                errors.append(f"component_status_enum: {e}")

            # Test 3: HealthMonitor with mock daemon
            self.logger.verbose("Test 3: HealthMonitor instantiation")
            try:
                mock_daemon = MagicMock()
                mock_daemon.event_logger = None
                mock_daemon.policy_engine = None
                mock_daemon.state_monitor = None
                monitor = HealthMonitor(daemon=mock_daemon)
                passed += 1
                details['instantiation'] = 'success'
            except Exception as e:
                failed += 1
                errors.append(f"instantiation: {e}")
                return PipelineTestResult(
                    name='health', passed=passed, failed=failed, skipped=0,
                    errors=errors, duration_ms=(time.perf_counter() - start) * 1000,
                    details=details
                )

            # Test 4: Heartbeat
            self.logger.verbose("Test 4: Heartbeat mechanism")
            try:
                monitor.heartbeat()
                passed += 1
                details['heartbeat'] = 'success'
            except Exception as e:
                failed += 1
                errors.append(f"heartbeat: {e}")

            # Test 5: Get health
            self.logger.verbose("Test 5: Get health")
            try:
                health = monitor.get_health()
                assert isinstance(health, HealthSnapshot)
                passed += 1
                details['get_health'] = 'success'
            except Exception as e:
                failed += 1
                errors.append(f"get_health: {e}")

            # Test 6: Get uptime
            self.logger.verbose("Test 6: Get uptime")
            try:
                uptime = monitor.get_uptime()
                assert isinstance(uptime, float) and uptime >= 0
                passed += 1
                details['uptime'] = uptime
            except Exception as e:
                failed += 1
                errors.append(f"get_uptime: {e}")

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
                assert daemon.policy_engine.get_current_mode() == BoundaryMode.OPEN
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
