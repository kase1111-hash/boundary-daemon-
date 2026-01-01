#!/usr/bin/env python3
"""
Boundary Daemon Build Script

Cross-platform build script that compiles the daemon into a standalone executable
using PyInstaller. Works on Windows, Linux, and macOS.

Usage:
    python build.py [options]

Options:
    --onefile       Create a single executable (default)
    --onedir        Create a directory with executable and dependencies
    --debug         Include debug symbols
    --clean         Clean build artifacts before building
    --skip-deps     Skip dependency installation
    --verbose       Show detailed build output
    --help, -h      Show this help message
"""

import os
import sys
import shutil
import subprocess
import argparse
import time
import platform
import json
import hashlib
import hmac
import stat
from pathlib import Path
from typing import List, Optional, Dict
from datetime import datetime


# ANSI color codes (disabled on Windows without proper terminal support)
class Colors:
    """ANSI color codes for terminal output."""

    def __init__(self):
        # Enable colors on Windows 10+ or Unix-like systems
        self.enabled = self._check_color_support()

    def _check_color_support(self) -> bool:
        """Check if terminal supports colors."""
        if not sys.stdout.isatty():
            return False
        if sys.platform == "win32":
            # Windows 10 build 14393+ supports ANSI
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
                return True
            except Exception:
                return False
        return True

    @property
    def GREEN(self) -> str:
        return "\033[92m" if self.enabled else ""

    @property
    def RED(self) -> str:
        return "\033[91m" if self.enabled else ""

    @property
    def YELLOW(self) -> str:
        return "\033[93m" if self.enabled else ""

    @property
    def CYAN(self) -> str:
        return "\033[96m" if self.enabled else ""

    @property
    def BOLD(self) -> str:
        return "\033[1m" if self.enabled else ""

    @property
    def RESET(self) -> str:
        return "\033[0m" if self.enabled else ""


colors = Colors()


def print_header(message: str) -> None:
    """Print a section header."""
    print(f"\n{colors.CYAN}{'=' * 60}{colors.RESET}")
    print(f"{colors.CYAN}{message}{colors.RESET}")
    print(f"{colors.CYAN}{'=' * 60}{colors.RESET}\n")


def print_step(step: int, total: int, message: str) -> None:
    """Print a build step."""
    print(f"{colors.YELLOW}[{step}/{total}] {message}{colors.RESET}")


def print_success(message: str) -> None:
    """Print a success message."""
    print(f"{colors.GREEN}  {message}{colors.RESET}")


def print_error(message: str) -> None:
    """Print an error message."""
    print(f"{colors.RED}ERROR: {message}{colors.RESET}")


def print_warning(message: str) -> None:
    """Print a warning message."""
    print(f"{colors.YELLOW}WARNING: {message}{colors.RESET}")


def print_info(message: str) -> None:
    """Print an info message."""
    print(f"  {message}")


def check_python_version() -> bool:
    """Ensure Python 3.8+ is being used."""
    if sys.version_info < (3, 8):
        print_error("Python 3.8 or higher is required")
        print_info(f"Current version: {sys.version}")
        return False
    print_info(f"Python version: {sys.version.split()[0]}")
    return True


def check_main_script(script_path: Path) -> bool:
    """Check if main script exists."""
    if not script_path.exists():
        print_error(f"Main script not found: {script_path}")
        return False
    print_info(f"Main script: {script_path} [OK]")
    return True


def check_packages() -> bool:
    """Check if required packages exist."""
    daemon_init = Path("daemon/__init__.py")
    api_init = Path("api/__init__.py")

    if not daemon_init.exists():
        print_error("daemon package not found")
        return False
    print_info("Daemon package: [OK]")

    if not api_init.exists():
        print_error("api package not found")
        return False
    print_info("API package: [OK]")

    return True


def install_pyinstaller() -> bool:
    """Install PyInstaller if not present."""
    try:
        import PyInstaller
        print_info(f"PyInstaller version: {PyInstaller.__version__}")
        return True
    except ImportError:
        print_info("Installing PyInstaller...")
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "pyinstaller", "--quiet"],
            capture_output=True
        )
        if result.returncode != 0:
            print_error("Failed to install PyInstaller")
            return False
        print_success("PyInstaller installed successfully")
        return True


def install_dependencies() -> bool:
    """Install project dependencies."""
    requirements_file = Path("requirements.txt")
    if not requirements_file.exists():
        print_warning("requirements.txt not found")
        return True

    print_info("Installing project dependencies...")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r", str(requirements_file), "--quiet"],
        capture_output=True
    )
    if result.returncode != 0:
        print_error("Failed to install dependencies")
        print_info(result.stderr.decode() if result.stderr else "Unknown error")
        return False
    print_success("Dependencies installed successfully")
    return True


def clean_build() -> None:
    """Remove previous build artifacts."""
    artifacts = ["build", "dist", "__pycache__"]
    for folder in artifacts:
        folder_path = Path(folder)
        if folder_path.exists():
            shutil.rmtree(folder_path)
            print_info(f"Removed: {folder}/")

    # Remove .spec files
    for spec_file in Path(".").glob("*.spec"):
        spec_file.unlink()
        print_info(f"Removed: {spec_file}")

    # Remove __pycache__ directories recursively
    for pycache in Path(".").rglob("__pycache__"):
        if pycache.is_dir():
            shutil.rmtree(pycache)

    print_success("Clean complete!")


def generate_signing_key(key_path: Path) -> bool:
    """Generate a signing key for manifest verification."""
    if key_path.exists():
        print_info(f"Signing key already exists: {key_path}")
        return True

    try:
        # Generate 32 bytes of cryptographically secure random data
        key_data = os.urandom(32)

        # Create parent directory if needed
        key_path.parent.mkdir(parents=True, exist_ok=True)

        # Write key with secure permissions
        if sys.platform != "win32":
            # Unix: use atomic create with correct permissions
            fd = os.open(
                str(key_path),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                stat.S_IRUSR | stat.S_IWUSR  # 0o600
            )
            try:
                os.write(fd, key_data)
            finally:
                os.close(fd)
        else:
            # Windows: write file normally
            key_path.write_bytes(key_data)

        print_success(f"Generated signing key: {key_path}")
        return True

    except FileExistsError:
        print_info(f"Signing key already exists: {key_path}")
        return True
    except Exception as e:
        print_error(f"Failed to generate signing key: {e}")
        return False


def calculate_file_hash(filepath: Path, algorithm: str = "sha256") -> str:
    """Calculate hash of a single file."""
    try:
        hasher = hashlib.new(algorithm)
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        print_warning(f"Failed to hash {filepath}: {e}")
        return ""


def scan_daemon_files(daemon_root: Path) -> Dict[str, Dict]:
    """Scan all daemon and api Python files."""
    files = {}
    exclude_patterns = ["__pycache__", ".pyc", ".pyo", ".git", ".pytest_cache"]

    for package in ["daemon", "api"]:
        package_path = daemon_root / package
        if not package_path.exists():
            continue

        for filepath in package_path.rglob("*.py"):
            # Check exclusions
            filepath_str = str(filepath)
            if any(pattern in filepath_str for pattern in exclude_patterns):
                continue

            rel_path = str(filepath.relative_to(daemon_root))
            file_hash = calculate_file_hash(filepath)
            if file_hash:
                stat_info = filepath.stat()
                files[rel_path] = {
                    'path': rel_path,
                    'hash': file_hash,
                    'size': stat_info.st_size,
                    'mtime': stat_info.st_mtime,
                }

    return files


def sign_manifest(manifest_data: Dict, signing_key: bytes) -> str:
    """Create HMAC signature for manifest."""
    # Exclude the signature field
    data_to_sign = {k: v for k, v in manifest_data.items() if k != 'signature'}
    canonical = json.dumps(data_to_sign, sort_keys=True, separators=(',', ':'))

    signature = hmac.new(
        signing_key,
        canonical.encode(),
        hashlib.sha256
    ).hexdigest()

    return signature


def generate_manifest(daemon_root: Path, key_path: Path, manifest_path: Path, version: str = "build") -> bool:
    """Generate a signed manifest for the daemon files."""
    try:
        # Load signing key
        if not key_path.exists():
            print_error(f"Signing key not found: {key_path}")
            return False

        signing_key = key_path.read_bytes()
        if len(signing_key) < 32:
            print_error(f"Signing key too short: {len(signing_key)} bytes")
            return False

        # Scan files
        files = scan_daemon_files(daemon_root)
        if not files:
            print_error("No files found to include in manifest")
            return False

        # Create manifest
        manifest = {
            'version': '1.0',
            'created_at': datetime.utcnow().isoformat() + 'Z',
            'daemon_version': version,
            'hash_algorithm': 'sha256',
            'files': files,
            'signature': '',
        }

        # Sign manifest
        manifest['signature'] = sign_manifest(manifest, signing_key)

        # Save manifest
        manifest_path.parent.mkdir(parents=True, exist_ok=True)

        # Make writable if exists
        if manifest_path.exists():
            try:
                manifest_path.chmod(0o644)
            except OSError:
                pass

        with open(manifest_path, 'w') as f:
            json.dump(manifest, f, indent=2)

        # Set read-only
        try:
            manifest_path.chmod(0o444)
        except OSError:
            pass

        print_success(f"Generated manifest with {len(files)} files: {manifest_path}")
        return True

    except Exception as e:
        print_error(f"Failed to generate manifest: {e}")
        return False


def setup_integrity_files() -> bool:
    """Set up signing key and manifest for the build."""
    daemon_root = Path(".")
    config_dir = daemon_root / "config"
    key_path = config_dir / "signing.key"
    manifest_path = config_dir / "manifest.json"

    # Generate signing key if needed
    if not generate_signing_key(key_path):
        return False

    # Generate manifest
    if not generate_manifest(daemon_root, key_path, manifest_path):
        return False

    return True


def get_hidden_imports() -> List[str]:
    """Get list of all hidden imports for daemon and api packages."""
    return [
        # C extension modules for cryptography
        "--hidden-import=cffi",
        "--hidden-import=_cffi_backend",
        "--hidden-import=nacl",
        "--hidden-import=nacl.bindings",
        "--hidden-import=nacl.signing",
        "--hidden-import=cryptography",
        "--hidden-import=cryptography.fernet",
        "--hidden-import=cryptography.hazmat.primitives",
        "--hidden-import=cryptography.hazmat.primitives.kdf.pbkdf2",
        "--hidden-import=cryptography.hazmat.backends",
        # YARA detection engine (optional but included if available)
        "--hidden-import=yara",
        # API package
        "--hidden-import=api",
        "--hidden-import=api.boundary_api",
        # Daemon core modules
        "--hidden-import=daemon",
        "--hidden-import=daemon.constants",
        "--hidden-import=daemon.state_monitor",
        "--hidden-import=daemon.policy_engine",
        "--hidden-import=daemon.tripwires",
        "--hidden-import=daemon.event_logger",
        "--hidden-import=daemon.signed_event_logger",
        "--hidden-import=daemon.boundary_daemon",
        "--hidden-import=daemon.memory_monitor",
        "--hidden-import=daemon.resource_monitor",
        "--hidden-import=daemon.health_monitor",
        "--hidden-import=daemon.queue_monitor",
        "--hidden-import=daemon.monitoring_report",
        "--hidden-import=daemon.privilege_manager",
        "--hidden-import=daemon.redundant_event_logger",
        "--hidden-import=daemon.integrations",
        # Daemon subpackages - airgap
        "--hidden-import=daemon.airgap",
        "--hidden-import=daemon.airgap.data_diode",
        "--hidden-import=daemon.airgap.qr_ceremony",
        "--hidden-import=daemon.airgap.sneakernet",
        # Daemon subpackages - alerts
        "--hidden-import=daemon.alerts",
        "--hidden-import=daemon.alerts.case_manager",
        # Daemon subpackages - api
        "--hidden-import=daemon.api",
        "--hidden-import=daemon.api.health",
        # Daemon subpackages - auth
        "--hidden-import=daemon.auth",
        "--hidden-import=daemon.auth.api_auth",
        "--hidden-import=daemon.auth.advanced_ceremony",
        "--hidden-import=daemon.auth.biometric_verifier",
        "--hidden-import=daemon.auth.enhanced_ceremony",
        "--hidden-import=daemon.auth.persistent_rate_limiter",
        "--hidden-import=daemon.auth.secure_token_storage",
        # Daemon subpackages - cli
        "--hidden-import=daemon.cli",
        "--hidden-import=daemon.cli.boundaryctl",
        "--hidden-import=daemon.cli.queryctl",
        "--hidden-import=daemon.cli.sandboxctl",
        # Daemon subpackages - compliance
        "--hidden-import=daemon.compliance",
        "--hidden-import=daemon.compliance.access_review",
        "--hidden-import=daemon.compliance.control_mapping",
        "--hidden-import=daemon.compliance.evidence_bundle",
        "--hidden-import=daemon.compliance.zk_proofs",
        # Daemon subpackages - config
        "--hidden-import=daemon.config",
        "--hidden-import=daemon.config.linter",
        "--hidden-import=daemon.config.secure_config",
        # Daemon subpackages - containment
        "--hidden-import=daemon.containment",
        "--hidden-import=daemon.containment.agent_profiler",
        # Daemon subpackages - crypto
        "--hidden-import=daemon.crypto",
        "--hidden-import=daemon.crypto.hsm_provider",
        "--hidden-import=daemon.crypto.post_quantum",
        # Daemon subpackages - detection
        "--hidden-import=daemon.detection",
        "--hidden-import=daemon.detection.event_publisher",
        "--hidden-import=daemon.detection.ioc_feeds",
        "--hidden-import=daemon.detection.mitre_attack",
        "--hidden-import=daemon.detection.sigma_engine",
        "--hidden-import=daemon.detection.yara_engine",
        # Daemon subpackages - distributed
        "--hidden-import=daemon.distributed",
        "--hidden-import=daemon.distributed.cluster_manager",
        "--hidden-import=daemon.distributed.coordinators",
        # Daemon subpackages - ebpf
        "--hidden-import=daemon.ebpf",
        "--hidden-import=daemon.ebpf.ebpf_observer",
        "--hidden-import=daemon.ebpf.policy_integration",
        "--hidden-import=daemon.ebpf.probes",
        # Daemon subpackages - enforcement
        "--hidden-import=daemon.enforcement",
        "--hidden-import=daemon.enforcement.disk_encryption",
        "--hidden-import=daemon.enforcement.firewall_integration",
        "--hidden-import=daemon.enforcement.mac_profiles",
        "--hidden-import=daemon.enforcement.network_enforcer",
        "--hidden-import=daemon.enforcement.process_enforcer",
        "--hidden-import=daemon.enforcement.protection_persistence",
        "--hidden-import=daemon.enforcement.secure_process_termination",
        "--hidden-import=daemon.enforcement.secure_profile_manager",
        "--hidden-import=daemon.enforcement.usb_enforcer",
        "--hidden-import=daemon.enforcement.windows_firewall",
        # Daemon subpackages - external_integrations
        "--hidden-import=daemon.external_integrations",
        "--hidden-import=daemon.external_integrations.siem",
        "--hidden-import=daemon.external_integrations.siem.cef_leef",
        "--hidden-import=daemon.external_integrations.siem.log_shipper",
        "--hidden-import=daemon.external_integrations.siem.sandbox_events",
        "--hidden-import=daemon.external_integrations.siem.verification_api",
        # Daemon subpackages - federation
        "--hidden-import=daemon.federation",
        "--hidden-import=daemon.federation.threat_mesh",
        # Daemon subpackages - hardware
        "--hidden-import=daemon.hardware",
        "--hidden-import=daemon.hardware.tpm_manager",
        # Daemon subpackages - identity
        "--hidden-import=daemon.identity",
        "--hidden-import=daemon.identity.identity_manager",
        "--hidden-import=daemon.identity.ldap_mapper",
        "--hidden-import=daemon.identity.oidc_validator",
        "--hidden-import=daemon.identity.pam_integration",
        # Daemon subpackages - integrity
        "--hidden-import=daemon.integrity",
        "--hidden-import=daemon.integrity.code_signer",
        "--hidden-import=daemon.integrity.integrity_verifier",
        # Daemon subpackages - intelligence
        "--hidden-import=daemon.intelligence",
        "--hidden-import=daemon.intelligence.mode_advisor",
        # Daemon subpackages - messages
        "--hidden-import=daemon.messages",
        "--hidden-import=daemon.messages.message_checker",
        # Daemon subpackages - pii
        "--hidden-import=daemon.pii",
        "--hidden-import=daemon.pii.bypass_resistant_detector",
        "--hidden-import=daemon.pii.detector",
        "--hidden-import=daemon.pii.filter",
        # Daemon subpackages - policy
        "--hidden-import=daemon.policy",
        "--hidden-import=daemon.policy.custom_policy_engine",
        # Daemon subpackages - sandbox
        "--hidden-import=daemon.sandbox",
        "--hidden-import=daemon.sandbox.cgroups",
        "--hidden-import=daemon.sandbox.mac_profiles",
        "--hidden-import=daemon.sandbox.namespace",
        "--hidden-import=daemon.sandbox.network_policy",
        "--hidden-import=daemon.sandbox.profile_config",
        "--hidden-import=daemon.sandbox.sandbox_manager",
        "--hidden-import=daemon.sandbox.seccomp_filter",
        # Daemon subpackages - security
        "--hidden-import=daemon.security",
        "--hidden-import=daemon.security.agent_attestation",
        "--hidden-import=daemon.security.antivirus",
        "--hidden-import=daemon.security.antivirus_gui",
        "--hidden-import=daemon.security.arp_security",
        "--hidden-import=daemon.security.clock_monitor",
        "--hidden-import=daemon.security.code_advisor",
        "--hidden-import=daemon.security.daemon_integrity",
        "--hidden-import=daemon.security.dns_security",
        "--hidden-import=daemon.security.file_integrity",
        "--hidden-import=daemon.security.hardening",
        "--hidden-import=daemon.security.native_dns_resolver",
        "--hidden-import=daemon.security.network_attestation",
        "--hidden-import=daemon.security.process_security",
        "--hidden-import=daemon.security.prompt_injection",
        "--hidden-import=daemon.security.rag_injection",
        "--hidden-import=daemon.security.response_guardrails",
        "--hidden-import=daemon.security.secure_memory",
        "--hidden-import=daemon.security.siem_integration",
        "--hidden-import=daemon.security.threat_intel",
        "--hidden-import=daemon.security.tool_validator",
        "--hidden-import=daemon.security.traffic_anomaly",
        "--hidden-import=daemon.security.wifi_security",
        # Daemon subpackages - storage
        "--hidden-import=daemon.storage",
        "--hidden-import=daemon.storage.append_only",
        "--hidden-import=daemon.storage.forensic_audit",
        "--hidden-import=daemon.storage.log_hardening",
        # Daemon subpackages - telemetry
        "--hidden-import=daemon.telemetry",
        "--hidden-import=daemon.telemetry.otel_setup",
        "--hidden-import=daemon.telemetry.prometheus_metrics",
        # Daemon subpackages - tui
        "--hidden-import=daemon.tui",
        "--hidden-import=daemon.tui.dashboard",
        # Daemon subpackages - utils
        "--hidden-import=daemon.utils",
        "--hidden-import=daemon.utils.error_handling",
        # Daemon subpackages - watchdog
        "--hidden-import=daemon.watchdog",
        "--hidden-import=daemon.watchdog.hardened_watchdog",
        "--hidden-import=daemon.watchdog.log_watchdog",
        # Daemon subpackages - blockchain
        "--hidden-import=daemon.blockchain",
        "--hidden-import=daemon.blockchain.validator_protection",
        "--hidden-import=daemon.blockchain.rpc_protection",
    ]


def build_executable(
    onefile: bool = True,
    debug: bool = False,
    noconfirm: bool = True,
    verbose: bool = False
) -> bool:
    """Build the executable using PyInstaller."""
    # Determine platform-specific settings
    separator = ";" if sys.platform == "win32" else ":"
    app_name = "boundary-daemon"
    main_script = Path("run_daemon.py")

    if not main_script.exists():
        print_error(f"Main script not found: {main_script}")
        return False

    # Build PyInstaller command
    # Note: Using explicit hidden imports instead of --collect-submodules for daemon/api
    # to avoid PyInstaller warnings about NoneType iteration errors
    cmd = [
        sys.executable, "-m", "PyInstaller",
        f"--name={app_name}",
        "--console",
        f"--add-data=daemon{separator}daemon",
        f"--add-data=api{separator}api",
    ]

    # Add all hidden imports
    cmd.extend(get_hidden_imports())

    # Collect submodules for external packages only
    cmd.extend([
        "--collect-submodules=nacl",
        "--collect-submodules=cffi",
        "--collect-submodules=cryptography",
        "--collect-submodules=yara",
    ])

    # Check for icon file
    icon_path = Path("assets/icon.ico")
    if icon_path.exists():
        cmd.append(f"--icon={icon_path}")
        print_info(f"Using icon: {icon_path}")

    if onefile:
        cmd.append("--onefile")
    else:
        cmd.append("--onedir")

    if debug:
        cmd.append("--debug=all")

    if noconfirm:
        cmd.append("--noconfirm")

    cmd.append("--clean")
    cmd.append(str(main_script))

    if verbose:
        print_info("Build command:")
        print_info(" ".join(cmd[:10]) + " ...")

    print()

    # Run PyInstaller
    result = subprocess.run(
        cmd,
        capture_output=not verbose,
        text=True
    )

    return result.returncode == 0


def post_build(onefile: bool = True) -> None:
    """Post-build tasks: copy configs, create run scripts."""
    dist_path = Path("dist")
    app_name = "boundary-daemon"

    # Copy config directory if it exists
    config_src = Path("config")
    if config_src.exists():
        config_dst = dist_path / "config"
        if config_dst.exists():
            shutil.rmtree(config_dst)
        shutil.copytree(config_src, config_dst)
        print_info("Copied configuration files to dist/config")

    # Create platform-specific run script
    if sys.platform == "win32":
        run_script = dist_path / "run-daemon.bat"
        run_script.write_text(
            '@echo off\n'
            'echo Starting Boundary Daemon...\n'
            f'"%~dp0{app_name}.exe" %*\n'
            'pause\n'
        )
        print_info(f"Created: {run_script}")
    else:
        run_script = dist_path / "run-daemon.sh"
        run_script.write_text(
            '#!/bin/bash\n'
            'echo "Starting Boundary Daemon..."\n'
            'DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"\n'
            f'"$DIR/{app_name}" "$@"\n'
        )
        run_script.chmod(0o755)
        print_info(f"Created: {run_script}")

    # Show executable size
    if onefile:
        exe_name = f"{app_name}.exe" if sys.platform == "win32" else app_name
        exe_path = dist_path / exe_name
        if exe_path.exists():
            size_mb = exe_path.stat().st_size / (1024 * 1024)
            print_info(f"Executable size: {size_mb:.1f} MB")


def print_build_summary(
    success: bool,
    build_time: float,
    onefile: bool,
    debug: bool
) -> None:
    """Print build summary."""
    app_name = "boundary-daemon"

    if success:
        print_header("BUILD SUCCESSFUL!")

        exe_name = f"{app_name}.exe" if sys.platform == "win32" else app_name
        if onefile:
            print_info(f"Executable: dist/{exe_name}")
        else:
            print_info(f"Directory: dist/{app_name}/")

        print_info(f"Build time: {build_time:.1f} seconds")
        print_info(f"Platform: {platform.system()} {platform.machine()}")
        print_info(f"Python: {sys.version.split()[0]}")
        if debug:
            print_info("Debug mode: enabled")

        print()
        print_info("To run the daemon:")
        if sys.platform == "win32":
            print_info(f"  cd dist && {exe_name}")
            print_info("  or: dist\\run-daemon.bat")
        else:
            print_info(f"  cd dist && ./{exe_name}")
            print_info("  or: ./dist/run-daemon.sh")
    else:
        print_header("BUILD FAILED!")
        print()
        print_info("Check the error messages above for details.")
        print()
        print_info("Common fixes:")
        print_info("  - Ensure Python 3.8+ is installed")
        print_info("  - Run: pip install pyinstaller")
        print_info("  - Run: pip install -r requirements.txt")
        print_info("  - Try: python build.py --clean")


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Build Boundary Daemon executable",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python build.py                  Build single executable
  python build.py --clean          Clean and build
  python build.py --onedir         Build as directory
  python build.py --debug --clean  Debug build with clean
  python build.py --verbose        Show detailed output
        """
    )
    parser.add_argument(
        "--onefile", action="store_true", default=True,
        help="Create a single executable (default)"
    )
    parser.add_argument(
        "--onedir", action="store_true",
        help="Create a directory with executable and dependencies"
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Include debug symbols"
    )
    parser.add_argument(
        "--clean", action="store_true",
        help="Clean build artifacts before building"
    )
    parser.add_argument(
        "--skip-deps", action="store_true",
        help="Skip dependency installation"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show detailed build output"
    )
    args = parser.parse_args()

    start_time = time.time()
    total_steps = 6

    print_header("Boundary Daemon Build Script")

    print_info(f"Build Mode: {'onedir' if args.onedir else 'onefile'}")
    print_info(f"Debug Mode: {args.debug}")
    print_info(f"Clean Build: {args.clean}")
    print_info(f"Platform: {platform.system()} {platform.machine()}")
    print()

    # Step 1: Pre-build checks
    print_step(1, total_steps, "Running pre-build checks...")
    if not check_python_version():
        return 1
    if not check_main_script(Path("run_daemon.py")):
        return 1
    if not check_packages():
        return 1
    print_success("Pre-build checks passed!")

    # Step 2: Clean if requested
    print_step(2, total_steps, "Cleaning previous build artifacts..." if args.clean else "Skipping clean (use --clean to enable)")
    if args.clean:
        clean_build()

    # Step 3: Install dependencies
    print_step(3, total_steps, "Installing dependencies..." if not args.skip_deps else "Skipping dependency installation (--skip-deps)")
    if not args.skip_deps:
        if not install_pyinstaller():
            return 1
        if not install_dependencies():
            return 1

    # Step 4: Generate integrity files (signing key and manifest)
    print_step(4, total_steps, "Generating integrity manifest...")
    if not setup_integrity_files():
        print_warning("Failed to generate integrity files - build will continue but runtime verification may fail")

    # Step 5: Setup build environment
    print_step(5, total_steps, "Setting up build environment...")
    Path("dist").mkdir(exist_ok=True)
    Path("build").mkdir(exist_ok=True)
    print_info("Created output directories")

    # Step 6: Build
    onefile = not args.onedir
    print_step(6, total_steps, "Building boundary-daemon...")
    success = build_executable(
        onefile=onefile,
        debug=args.debug,
        noconfirm=True,
        verbose=args.verbose
    )

    # Post-build tasks
    if success:
        print()
        print(f"{colors.CYAN}Post-build tasks...{colors.RESET}")
        post_build(onefile=onefile)

    # Print summary
    build_time = time.time() - start_time
    print_build_summary(success, build_time, onefile, args.debug)

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
