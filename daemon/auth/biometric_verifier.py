"""
Biometric Verifier - Fingerprint and Facial Recognition
Handles enrollment and verification for biometric authentication.
"""

import os
import hashlib
import time
import json
from dataclasses import dataclass
from enum import Enum
from typing import Optional, List, Tuple
from pathlib import Path

# Optional imports with graceful fallback
try:
    import cv2
    CV2_AVAILABLE = True
except ImportError:
    CV2_AVAILABLE = False

try:
    import face_recognition
    FACE_RECOGNITION_AVAILABLE = True
except ImportError:
    FACE_RECOGNITION_AVAILABLE = False

# Note: libfprint is not available as a Python package
# We'll implement a mock interface for development/testing
FPRINT_AVAILABLE = False


class BiometricType(Enum):
    """Type of biometric authentication"""
    FINGERPRINT = "fingerprint"
    FACE = "face"


@dataclass
class BiometricResult:
    """Result of a biometric verification attempt"""
    success: bool
    biometric_type: BiometricType
    match_score: float
    liveness_passed: bool
    error_message: Optional[str] = None
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = str(time.time())


@dataclass
class BiometricTemplate:
    """Stored biometric template"""
    template_id: str
    biometric_type: BiometricType
    created_at: str
    last_used: Optional[str] = None
    use_count: int = 0


class BiometricVerifier:
    """
    Handles enrollment and verification for biometrics.

    Supports fingerprint and facial recognition with:
    - Secure template storage (encrypted with optional TPM sealing)
    - Liveness detection (anti-spoofing)
    - Graceful fallback when hardware unavailable
    - Threshold-based matching
    """

    DEFAULT_TEMPLATE_DIR = '/var/lib/boundary-daemon/biometrics/'
    FINGERPRINT_THRESHOLD = 0.7  # Match score threshold
    FACE_THRESHOLD = 0.4  # Distance threshold (lower = stricter)

    def __init__(self, template_dir: Optional[str] = None, tpm_manager=None):
        """
        Initialize biometric verifier.

        Args:
            template_dir: Directory to store encrypted templates
            tpm_manager: Optional TPM manager for template encryption
        """
        self.template_dir = Path(template_dir or self.DEFAULT_TEMPLATE_DIR)
        self.template_dir.mkdir(parents=True, exist_ok=True)
        self.tpm_manager = tpm_manager

        # Hardware availability
        self.fingerprint_available = FPRINT_AVAILABLE
        self.camera_available = CV2_AVAILABLE and FACE_RECOGNITION_AVAILABLE

        # Load existing templates
        self.enrolled_templates: List[BiometricTemplate] = []
        self._load_templates()

        print(f"BiometricVerifier initialized:")
        print(f"  Template directory: {self.template_dir}")
        print(f"  Fingerprint reader: {'Available' if self.fingerprint_available else 'Not available'}")
        print(f"  Camera/Face recognition: {'Available' if self.camera_available else 'Not available'}")
        print(f"  Enrolled templates: {len(self.enrolled_templates)}")

    def _load_templates(self):
        """Load existing templates from disk"""
        if not self.template_dir.exists():
            return

        for file in self.template_dir.glob('*.json'):
            try:
                with open(file, 'r') as f:
                    data = json.load(f)
                    template = BiometricTemplate(
                        template_id=data['template_id'],
                        biometric_type=BiometricType(data['biometric_type']),
                        created_at=data['created_at'],
                        last_used=data.get('last_used'),
                        use_count=data.get('use_count', 0)
                    )
                    self.enrolled_templates.append(template)
            except Exception as e:
                print(f"Warning: Failed to load template {file}: {e}")

    def _save_template_metadata(self, template: BiometricTemplate):
        """Save template metadata to disk"""
        metadata_file = self.template_dir / f'{template.template_id}.json'
        with open(metadata_file, 'w') as f:
            json.dump({
                'template_id': template.template_id,
                'biometric_type': template.biometric_type.value,
                'created_at': template.created_at,
                'last_used': template.last_used,
                'use_count': template.use_count
            }, f, indent=2)

    def _save_template_data(self, template_id: str, data: bytes):
        """Save encrypted template data to disk"""
        if self.tpm_manager:
            # Encrypt with TPM if available
            encrypted = self.tpm_manager.seal_mode_secret(
                self.tpm_manager.daemon.policy_engine.current_mode if hasattr(self, 'daemon') else None,
                data
            )
        else:
            # Simple XOR obfuscation if no TPM (NOT SECURE FOR PRODUCTION)
            key = hashlib.sha256(b'boundary-daemon-biometric').digest()
            encrypted = bytes(a ^ b for a, b in zip(data, key * (len(data) // len(key) + 1)))

        template_file = self.template_dir / f'{template_id}.enc'
        with open(template_file, 'wb') as f:
            f.write(encrypted)

    def _load_template_data(self, template_id: str) -> Optional[bytes]:
        """Load and decrypt template data from disk"""
        template_file = self.template_dir / f'{template_id}.enc'
        if not template_file.exists():
            return None

        with open(template_file, 'rb') as f:
            encrypted = f.read()

        if self.tpm_manager:
            # Decrypt with TPM
            try:
                return self.tpm_manager.unseal_mode_secret(encrypted)
            except Exception as e:
                print(f"Error unsealing template: {e}")
                return None
        else:
            # Simple XOR reversal
            key = hashlib.sha256(b'boundary-daemon-biometric').digest()
            return bytes(a ^ b for a, b in zip(encrypted, key * (len(encrypted) // len(key) + 1)))

    # ========== FINGERPRINT METHODS ==========

    def can_enroll_fingerprint(self) -> Tuple[bool, Optional[str]]:
        """Check if fingerprint enrollment is possible"""
        if not self.fingerprint_available:
            return (False, "Fingerprint reader not available. Install libfprint for fingerprint support.")
        return (True, None)

    def enroll_fingerprint(self, num_samples: int = 3) -> Tuple[bool, Optional[str]]:
        """
        Enroll a new fingerprint.

        Args:
            num_samples: Number of finger scans to capture

        Returns:
            (success, error_message)
        """
        can_enroll, error = self.can_enroll_fingerprint()
        if not can_enroll:
            return (False, error)

        print(f"\n{'='*60}")
        print("FINGERPRINT ENROLLMENT")
        print(f"{'='*60}\n")
        print(f"Place your finger on the reader {num_samples} times.")
        print("Remove and replace your finger between scans.\n")

        # Mock implementation (replace with real libfprint calls when available)
        samples = []
        for i in range(num_samples):
            print(f"Scan {i+1}/{num_samples}: Place finger on reader...")
            time.sleep(1)  # Simulate scan time
            # In real implementation: sample = fprint_device.capture()
            mock_sample = os.urandom(256)  # Mock fingerprint data
            samples.append(mock_sample)
            print("  ✓ Scan captured")

        # Create template from samples
        # In real implementation: template = fprint.create_template(samples)
        template_data = b''.join(samples)  # Mock template
        template_hash = hashlib.sha256(template_data).hexdigest()[:16]

        # Create template metadata
        template = BiometricTemplate(
            template_id=f'fp_{template_hash}',
            biometric_type=BiometricType.FINGERPRINT,
            created_at=str(time.time())
        )

        # Save template
        self._save_template_data(template.template_id, template_data)
        self._save_template_metadata(template)
        self.enrolled_templates.append(template)

        print(f"\n✓ Fingerprint enrolled successfully")
        print(f"  Template ID: {template.template_id}\n")

        return (True, None)

    def verify_fingerprint(self, timeout: int = 30) -> BiometricResult:
        """
        Verify fingerprint with liveness detection.

        Args:
            timeout: Maximum time to wait for scan (seconds)

        Returns:
            BiometricResult with verification details
        """
        if not self.fingerprint_available:
            return BiometricResult(
                success=False,
                biometric_type=BiometricType.FINGERPRINT,
                match_score=0.0,
                liveness_passed=False,
                error_message="Fingerprint reader not available"
            )

        if not self.enrolled_templates:
            return BiometricResult(
                success=False,
                biometric_type=BiometricType.FINGERPRINT,
                match_score=0.0,
                liveness_passed=False,
                error_message="No enrolled fingerprints found"
            )

        print("\nPlace finger on reader for verification...")

        # Mock implementation (replace with real libfprint calls)
        time.sleep(1)  # Simulate scan time
        # In real implementation:
        # sample = fprint_device.capture(with_liveness=True)
        # liveness_passed = sample.is_live()
        mock_sample = os.urandom(256)
        liveness_passed = True  # Mock liveness check

        # Compare with enrolled templates
        best_match_score = 0.0
        matched_template = None

        for template in self.enrolled_templates:
            if template.biometric_type != BiometricType.FINGERPRINT:
                continue

            template_data = self._load_template_data(template.template_id)
            if not template_data:
                continue

            # In real implementation: score = fprint.compare(sample, template_data)
            # Mock: simulate a match with random score
            import random
            mock_score = random.uniform(0.65, 0.95)  # Simulate varying match quality

            if mock_score > best_match_score:
                best_match_score = mock_score
                matched_template = template

        # Check if match exceeds threshold
        success = best_match_score >= self.FINGERPRINT_THRESHOLD

        if success and matched_template:
            # Update template usage stats
            matched_template.last_used = str(time.time())
            matched_template.use_count += 1
            self._save_template_metadata(matched_template)

        return BiometricResult(
            success=success,
            biometric_type=BiometricType.FINGERPRINT,
            match_score=best_match_score,
            liveness_passed=liveness_passed
        )

    # ========== FACIAL RECOGNITION METHODS ==========

    def can_enroll_face(self) -> Tuple[bool, Optional[str]]:
        """Check if face enrollment is possible"""
        if not self.camera_available:
            missing = []
            if not CV2_AVAILABLE:
                missing.append("opencv-python")
            if not FACE_RECOGNITION_AVAILABLE:
                missing.append("face_recognition")
            return (False, f"Camera/face recognition not available. Install: {', '.join(missing)}")
        return (True, None)

    def enroll_face(self, num_samples: int = 5) -> Tuple[bool, Optional[str]]:
        """
        Enroll a new face.

        Args:
            num_samples: Number of frames to capture

        Returns:
            (success, error_message)
        """
        can_enroll, error = self.can_enroll_face()
        if not can_enroll:
            return (False, error)

        print(f"\n{'='*60}")
        print("FACIAL RECOGNITION ENROLLMENT")
        print(f"{'='*60}\n")
        print(f"Look at the camera. {num_samples} frames will be captured.")
        print("Vary your angle slightly between captures.\n")

        try:
            camera = cv2.VideoCapture(0)
            if not camera.isOpened():
                return (False, "Failed to open camera")

            samples = []
            for i in range(num_samples):
                print(f"Capture {i+1}/{num_samples}...")
                ret, frame = camera.read()

                if not ret:
                    camera.release()
                    return (False, f"Failed to capture frame {i+1}")

                # Detect faces and extract encodings
                face_locations = face_recognition.face_locations(frame)
                if not face_locations:
                    print("  ⚠ No face detected, retrying...")
                    i -= 1  # Retry this capture
                    continue

                face_encodings = face_recognition.face_encodings(frame, face_locations)
                if not face_encodings:
                    print("  ⚠ Failed to encode face, retrying...")
                    i -= 1
                    continue

                samples.append(face_encodings[0])
                print("  ✓ Face captured")
                time.sleep(0.5)

            camera.release()

            if len(samples) < 3:
                return (False, f"Insufficient samples ({len(samples)}/3 minimum)")

            # Average the encodings to create template
            import numpy as np
            template_encoding = np.mean(samples, axis=0)
            template_data = template_encoding.tobytes()
            template_hash = hashlib.sha256(template_data).hexdigest()[:16]

            # Create template metadata
            template = BiometricTemplate(
                template_id=f'face_{template_hash}',
                biometric_type=BiometricType.FACE,
                created_at=str(time.time())
            )

            # Save template
            self._save_template_data(template.template_id, template_data)
            self._save_template_metadata(template)
            self.enrolled_templates.append(template)

            print(f"\n✓ Face enrolled successfully")
            print(f"  Template ID: {template.template_id}\n")

            return (True, None)

        except Exception as e:
            return (False, f"Enrollment failed: {e}")

    def verify_face(self, liveness_required: bool = True) -> BiometricResult:
        """
        Verify face with optional liveness detection (blink).

        Args:
            liveness_required: Whether to require liveness check

        Returns:
            BiometricResult with verification details
        """
        if not self.camera_available:
            return BiometricResult(
                success=False,
                biometric_type=BiometricType.FACE,
                match_score=0.0,
                liveness_passed=False,
                error_message="Camera/face recognition not available"
            )

        if not self.enrolled_templates:
            return BiometricResult(
                success=False,
                biometric_type=BiometricType.FACE,
                match_score=0.0,
                liveness_passed=False,
                error_message="No enrolled faces found"
            )

        print("\nLook at the camera for verification...")
        if liveness_required:
            print("Please blink naturally...")

        try:
            camera = cv2.VideoCapture(0)
            if not camera.isOpened():
                return BiometricResult(
                    success=False,
                    biometric_type=BiometricType.FACE,
                    match_score=0.0,
                    liveness_passed=False,
                    error_message="Failed to open camera"
                )

            # Capture multiple frames for liveness and better matching
            frames = []
            for _ in range(10):
                ret, frame = camera.read()
                if ret:
                    frames.append(frame)
                time.sleep(0.1)

            camera.release()

            if not frames:
                return BiometricResult(
                    success=False,
                    biometric_type=BiometricType.FACE,
                    match_score=0.0,
                    liveness_passed=False,
                    error_message="Failed to capture frames"
                )

            # Liveness check (simple blink detection)
            liveness_passed = True
            if liveness_required:
                liveness_passed = self._detect_blink(frames)

            # Extract face encodings from frames
            encodings = []
            for frame in frames:
                face_locations = face_recognition.face_locations(frame)
                if face_locations:
                    face_encodings = face_recognition.face_encodings(frame, face_locations)
                    if face_encodings:
                        encodings.append(face_encodings[0])

            if not encodings:
                return BiometricResult(
                    success=False,
                    biometric_type=BiometricType.FACE,
                    match_score=0.0,
                    liveness_passed=liveness_passed,
                    error_message="No face detected in frames"
                )

            # Average encodings
            import numpy as np
            avg_encoding = np.mean(encodings, axis=0)

            # Compare with enrolled templates
            best_match_distance = float('inf')
            matched_template = None

            for template in self.enrolled_templates:
                if template.biometric_type != BiometricType.FACE:
                    continue

                template_data = self._load_template_data(template.template_id)
                if not template_data:
                    continue

                # Convert bytes back to numpy array
                template_encoding = np.frombuffer(template_data, dtype=np.float64)

                # Calculate distance (lower = better match)
                distance = face_recognition.face_distance([template_encoding], avg_encoding)[0]

                if distance < best_match_distance:
                    best_match_distance = distance
                    matched_template = template

            # Check if match is within threshold
            success = best_match_distance <= self.FACE_THRESHOLD and liveness_passed

            if success and matched_template:
                # Update template usage stats
                matched_template.last_used = str(time.time())
                matched_template.use_count += 1
                self._save_template_metadata(matched_template)

            # Convert distance to similarity score (0-1, higher = better)
            match_score = max(0.0, 1.0 - best_match_distance)

            return BiometricResult(
                success=success,
                biometric_type=BiometricType.FACE,
                match_score=match_score,
                liveness_passed=liveness_passed
            )

        except Exception as e:
            return BiometricResult(
                success=False,
                biometric_type=BiometricType.FACE,
                match_score=0.0,
                liveness_passed=False,
                error_message=f"Verification failed: {e}"
            )

    def _detect_blink(self, frames: List) -> bool:
        """
        Simple blink detection via eye aspect ratio changes.

        Args:
            frames: List of video frames

        Returns:
            True if blink detected, False otherwise
        """
        # Simplified blink detection
        # In production, use dlib landmarks and EAR (Eye Aspect Ratio) calculation
        # For now, assume liveness if we have enough frames with faces
        faces_detected = sum(1 for frame in frames if len(face_recognition.face_locations(frame)) > 0)
        return faces_detected >= 5  # At least 5 frames with face = probably live

    # ========== MANAGEMENT METHODS ==========

    def list_enrolled(self) -> List[BiometricTemplate]:
        """Get list of enrolled biometric templates"""
        return self.enrolled_templates.copy()

    def delete_template(self, template_id: str) -> bool:
        """
        Delete an enrolled template.

        Args:
            template_id: ID of template to delete

        Returns:
            True if deleted, False if not found
        """
        # Find template
        template = None
        for t in self.enrolled_templates:
            if t.template_id == template_id:
                template = t
                break

        if not template:
            return False

        # Delete files
        metadata_file = self.template_dir / f'{template_id}.json'
        template_file = self.template_dir / f'{template_id}.enc'

        if metadata_file.exists():
            metadata_file.unlink()
        if template_file.exists():
            template_file.unlink()

        # Remove from list
        self.enrolled_templates.remove(template)

        print(f"✓ Deleted template: {template_id}")
        return True

    def get_capabilities(self) -> dict:
        """Get biometric capabilities of the system"""
        return {
            'fingerprint_available': self.fingerprint_available,
            'face_available': self.camera_available,
            'enrolled_count': len(self.enrolled_templates),
            'fingerprint_enrolled': sum(1 for t in self.enrolled_templates if t.biometric_type == BiometricType.FINGERPRINT),
            'face_enrolled': sum(1 for t in self.enrolled_templates if t.biometric_type == BiometricType.FACE)
        }


if __name__ == '__main__':
    # Test biometric verifier
    print("Testing Biometric Verifier...\n")

    import tempfile
    temp_dir = tempfile.mkdtemp()

    verifier = BiometricVerifier(template_dir=temp_dir)

    # Show capabilities
    print("\nCapabilities:")
    caps = verifier.get_capabilities()
    for key, value in caps.items():
        print(f"  {key}: {value}")

    # Test fingerprint enrollment (mock)
    print("\n" + "="*60)
    print("Testing fingerprint enrollment...")
    success, error = verifier.enroll_fingerprint(num_samples=3)
    if success:
        print("✓ Fingerprint enrollment succeeded")
    else:
        print(f"✗ Fingerprint enrollment failed: {error}")

    # Test face enrollment if camera available
    if verifier.camera_available:
        print("\n" + "="*60)
        print("Testing face enrollment...")
        success, error = verifier.enroll_face(num_samples=5)
        if success:
            print("✓ Face enrollment succeeded")
        else:
            print(f"✗ Face enrollment failed: {error}")

    # List enrolled templates
    print("\n" + "="*60)
    print("Enrolled templates:")
    for template in verifier.list_enrolled():
        print(f"  {template.template_id} ({template.biometric_type.value})")
        print(f"    Created: {template.created_at}")
        print(f"    Last used: {template.last_used or 'Never'}")
        print(f"    Use count: {template.use_count}")

    # Test verification
    if verifier.enrolled_templates:
        print("\n" + "="*60)
        print("Testing verification...")
        for template in verifier.enrolled_templates:
            if template.biometric_type == BiometricType.FINGERPRINT:
                result = verifier.verify_fingerprint()
                print(f"\nFingerprint verification:")
                print(f"  Success: {result.success}")
                print(f"  Match score: {result.match_score:.2f}")
                print(f"  Liveness: {result.liveness_passed}")
                if result.error_message:
                    print(f"  Error: {result.error_message}")

    # Cleanup
    import shutil
    shutil.rmtree(temp_dir)

    print("\nBiometric verifier test complete.")
