"""
Enhanced Ceremony Manager with Biometric Authentication
Extends the base CeremonyManager to support biometric verification.
"""

import time
from typing import Optional, Callable
from datetime import datetime

from ..integrations import CeremonyManager
from ..event_logger import EventType
from .biometric_verifier import BiometricVerifier, BiometricType, BiometricResult


class BiometricCeremonyConfig:
    """Configuration for biometric ceremonies"""
    def __init__(self):
        self.enabled = True
        self.preferred_method = 'any'  # 'fingerprint', 'face', or 'any'
        self.require_liveness = True
        self.fallback_to_keyboard = True
        self.cooldown_on_failure = 30  # seconds


class EnhancedCeremonyManager(CeremonyManager):
    """
    Enhanced ceremony manager with biometric authentication.

    Extends the base CeremonyManager to support:
    - Fingerprint verification
    - Facial recognition
    - Liveness detection
    - Graceful fallback to keyboard when hardware unavailable
    - Comprehensive audit logging
    """

    def __init__(self, daemon, biometric_verifier: Optional[BiometricVerifier] = None,
                 config: Optional[BiometricCeremonyConfig] = None,
                 cooldown_seconds: int = 30):
        """
        Initialize enhanced ceremony manager.

        Args:
            daemon: Reference to BoundaryDaemon instance
            biometric_verifier: BiometricVerifier instance (optional)
            config: BiometricCeremonyConfig (optional)
            cooldown_seconds: Delay between override steps
        """
        super().__init__(daemon, cooldown_seconds)
        self.biometric = biometric_verifier
        self.biometric_config = config or BiometricCeremonyConfig()
        self._failed_attempts = 0
        self._last_failure_time: Optional[float] = None

    def _check_failure_cooldown(self) -> tuple[bool, Optional[str]]:
        """
        Check if we're in cooldown period after failures.

        Returns:
            (can_proceed, error_message)
        """
        if self._last_failure_time is None:
            return (True, None)

        cooldown = self.biometric_config.cooldown_on_failure
        elapsed = time.time() - self._last_failure_time

        if elapsed < cooldown:
            remaining = int(cooldown - elapsed)
            return (False, f"Cooldown active. Wait {remaining} seconds before retry.")

        # Cooldown expired, reset
        self._failed_attempts = 0
        self._last_failure_time = None
        return (True, None)

    def _perform_biometric_verification(self) -> tuple[bool, str, Optional[BiometricResult]]:
        """
        Perform biometric verification based on configuration.

        Returns:
            (success, message, result)
        """
        if not self.biometric:
            return (False, "Biometric verifier not available", None)

        if not self.biometric_config.enabled:
            return (False, "Biometric authentication disabled", None)

        # Check failure cooldown
        can_proceed, error_msg = self._check_failure_cooldown()
        if not can_proceed:
            return (False, error_msg, None)

        # Get capabilities
        caps = self.biometric.get_capabilities()

        # Determine which method to use
        preferred = self.biometric_config.preferred_method
        result = None

        if preferred == 'fingerprint' or preferred == 'any':
            if caps['fingerprint_available'] and caps['fingerprint_enrolled'] > 0:
                print("\n→ Biometric verification: FINGERPRINT")
                result = self.biometric.verify_fingerprint()

                # Log attempt
                self._log_biometric_attempt(result)

                if result.success:
                    return (True, "Fingerprint verified successfully", result)
                elif preferred == 'fingerprint':
                    # Fingerprint was required but failed
                    self._handle_failed_attempt()
                    return (False, result.error_message or "Fingerprint verification failed", result)

        if preferred == 'face' or (preferred == 'any' and result is None):
            if caps['face_available'] and caps['face_enrolled'] > 0:
                print("\n→ Biometric verification: FACIAL RECOGNITION")
                result = self.biometric.verify_face(
                    liveness_required=self.biometric_config.require_liveness
                )

                # Log attempt
                self._log_biometric_attempt(result)

                if result.success:
                    return (True, "Face verified successfully", result)
                elif preferred == 'face':
                    # Face was required but failed
                    self._handle_failed_attempt()
                    return (False, result.error_message or "Face verification failed", result)

        # All methods failed or unavailable
        if result:
            self._handle_failed_attempt()
            return (False, result.error_message or "Biometric verification failed", result)
        else:
            return (False, "No biometric methods available or enrolled", None)

    def _log_biometric_attempt(self, result: BiometricResult):
        """Log biometric attempt to event logger"""
        self.daemon.event_logger.log_event(
            EventType.BIOMETRIC_ATTEMPT,
            f"Biometric {result.biometric_type.value} verification: {'SUCCESS' if result.success else 'FAILED'}",
            metadata={
                'biometric_type': result.biometric_type.value,
                'success': result.success,
                'match_score': result.match_score,
                'liveness_passed': result.liveness_passed,
                'error': result.error_message,
                'timestamp': result.timestamp
            }
        )

    def _handle_failed_attempt(self):
        """Handle a failed biometric attempt"""
        self._failed_attempts += 1
        self._last_failure_time = time.time()

        if self._failed_attempts >= 3:
            print(f"\n⚠ Multiple failed attempts ({self._failed_attempts})")
            print(f"   Cooldown: {self.biometric_config.cooldown_on_failure} seconds")

    def initiate_override(self, action: str, reason: str,
                         confirmation_callback: Optional[Callable] = None,
                         require_biometric: bool = True) -> tuple[bool, str]:
        """
        Initiate a human override ceremony with optional biometric verification.

        Args:
            action: Description of the action being overridden
            reason: Reason for the override
            confirmation_callback: Optional function to get confirmation (for testing)
            require_biometric: Whether to require biometric verification

        Returns:
            (success, message)
        """
        print("\n" + "=" * 70)
        print("HUMAN OVERRIDE CEREMONY INITIATED")
        print("=" * 70)
        print(f"Action: {action}")
        print(f"Reason: {reason}")
        print("=" * 70)

        # Log ceremony initiation
        self.daemon.event_logger.log_event(
            EventType.OVERRIDE,
            f"Override ceremony initiated: {action}",
            metadata={
                'action': action,
                'reason': reason,
                'status': 'initiated',
                'biometric_required': require_biometric and self.biometric_config.enabled
            }
        )

        # Step 1: Biometric verification (if enabled and available)
        if require_biometric and self.biometric_config.enabled and self.biometric:
            print("\nStep 1/3: Biometric verification...")

            success, message, result = self._perform_biometric_verification()

            if success:
                print(f"✓ {message}")
                print(f"  Match score: {result.match_score:.2f}")
                print(f"  Liveness: {'PASSED' if result.liveness_passed else 'FAILED'}")
            elif not self.biometric_config.fallback_to_keyboard:
                # Biometric required, no fallback allowed
                print(f"✗ {message}")
                print("\n→ Biometric verification required. Ceremony FAILED.")

                self.daemon.event_logger.log_event(
                    EventType.OVERRIDE,
                    f"Override ceremony failed: {action}",
                    metadata={
                        'action': action,
                        'reason': reason,
                        'status': 'failed',
                        'failure_reason': 'biometric_verification_failed'
                    }
                )

                return (False, message)
            else:
                # Fall back to keyboard
                print(f"⚠ {message}")
                print("→ Falling back to keyboard ceremony...")

        # Step 2 (or 1 if no biometric): Verify human presence via keyboard
        step_num = 2 if (require_biometric and self.biometric_config.enabled and self.biometric) else 1
        print(f"\nStep {step_num}/3: Verifying human presence...")
        print("Type the following phrase exactly:")
        print("\n  'I understand the consequences of this override'\n")

        if confirmation_callback:
            user_input = confirmation_callback()
        else:
            user_input = input("Enter phrase: ")

        expected = "I understand the consequences of this override"
        if user_input != expected:
            print("\n✗ Phrase mismatch. Ceremony FAILED.")

            self.daemon.event_logger.log_event(
                EventType.OVERRIDE,
                f"Override ceremony failed: {action}",
                metadata={
                    'action': action,
                    'reason': reason,
                    'status': 'failed',
                    'failure_reason': 'phrase_mismatch'
                }
            )

            return (False, "Verification phrase incorrect")

        print("✓ Human presence verified")

        # Step 3: Cooldown period
        step_num += 1
        print(f"\nStep {step_num}/3: Mandatory cooldown period...")
        print(f"Please wait {self.cooldown_seconds} seconds to confirm intent...")

        # Log cooldown start
        self.daemon.event_logger.log_event(
            EventType.OVERRIDE,
            f"Override ceremony cooldown: {action}",
            metadata={
                'action': action,
                'cooldown_seconds': self.cooldown_seconds,
                'status': 'cooldown'
            }
        )

        # Cooldown countdown
        for remaining in range(self.cooldown_seconds, 0, -1):
            if remaining % 5 == 0 or remaining <= 3:
                print(f"  {remaining} seconds remaining...")
            time.sleep(1)

        print("✓ Cooldown complete")

        # Final confirmation
        print(f"\nFinal confirmation required.")
        print(f"Type 'CONFIRM' to complete the override:\n")

        if confirmation_callback:
            final_input = confirmation_callback()
        else:
            final_input = input("Enter confirmation: ")

        if final_input != "CONFIRM":
            print("\n✗ Final confirmation failed. Ceremony ABORTED.")

            self.daemon.event_logger.log_event(
                EventType.OVERRIDE,
                f"Override ceremony aborted: {action}",
                metadata={
                    'action': action,
                    'reason': reason,
                    'status': 'aborted',
                    'failure_reason': 'final_confirmation_failed'
                }
            )

            return (False, "Final confirmation incorrect")

        print("\n" + "=" * 70)
        print("✓ OVERRIDE CEREMONY COMPLETED SUCCESSFULLY")
        print("=" * 70)

        # Log successful ceremony
        self.daemon.event_logger.log_event(
            EventType.OVERRIDE,
            f"Override ceremony SUCCESS: {action}",
            metadata={
                'action': action,
                'reason': reason,
                'status': 'success'
            }
        )

        self._last_ceremony = datetime.utcnow()

        return (True, "Override ceremony completed successfully")

    def perform_quick_ceremony(self, action: str) -> bool:
        """
        Perform a quick ceremony with just biometric verification.

        Useful for less critical operations where full ceremony is overkill.

        Args:
            action: Description of the action

        Returns:
            True if ceremony succeeds, False otherwise
        """
        if not self.biometric or not self.biometric_config.enabled:
            print(f"\nQuick ceremony not available (biometrics required)")
            return False

        print(f"\n→ Quick ceremony: {action}")

        success, message, result = self._perform_biometric_verification()

        if success:
            print(f"✓ {message}")

            self.daemon.event_logger.log_event(
                EventType.OVERRIDE,
                f"Quick ceremony SUCCESS: {action}",
                metadata={
                    'action': action,
                    'ceremony_type': 'quick',
                    'status': 'success',
                    'biometric_type': result.biometric_type.value if result else None
                }
            )

            return True
        else:
            print(f"✗ {message}")

            self.daemon.event_logger.log_event(
                EventType.OVERRIDE,
                f"Quick ceremony FAILED: {action}",
                metadata={
                    'action': action,
                    'ceremony_type': 'quick',
                    'status': 'failed',
                    'error': message
                }
            )

            return False

    def get_ceremony_stats(self) -> dict:
        """Get ceremony statistics"""
        return {
            'biometric_enabled': self.biometric_config.enabled if self.biometric else False,
            'biometric_available': self.biometric is not None,
            'failed_attempts': self._failed_attempts,
            'cooldown_active': self._last_failure_time is not None and
                              (time.time() - self._last_failure_time) < self.biometric_config.cooldown_on_failure,
            'last_ceremony': self._last_ceremony.isoformat() if self._last_ceremony else None
        }


if __name__ == '__main__':
    # Test enhanced ceremony manager
    print("Testing Enhanced Ceremony Manager...\n")

    # Mock daemon class
    class MockDaemon:
        class MockEventLogger:
            def log_event(self, event_type, details, metadata=None):
                print(f"[LOG] {event_type.value}: {details}")

        event_logger = MockEventLogger()

    # Create verifier
    import tempfile
    temp_dir = tempfile.mkdtemp()
    verifier = BiometricVerifier(template_dir=temp_dir)

    # Create enhanced ceremony manager
    daemon = MockDaemon()
    ceremony = EnhancedCeremonyManager(
        daemon=daemon,
        biometric_verifier=verifier,
        cooldown_seconds=5  # Short cooldown for testing
    )

    # Show stats
    print("\nCeremony Stats:")
    stats = ceremony.get_ceremony_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")

    # Test quick ceremony (should fail - no enrolled biometrics)
    print("\n" + "="*60)
    print("Testing quick ceremony (no biometrics enrolled)...")
    result = ceremony.perform_quick_ceremony("Test quick access")

    # Cleanup
    import shutil
    shutil.rmtree(temp_dir)

    print("\nEnhanced ceremony manager test complete.")
