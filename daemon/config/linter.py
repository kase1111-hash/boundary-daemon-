"""
Configuration Linter - Validate Boundary Daemon Configuration

Phase 2 Operational Excellence: Prevents misconfigurations that could
weaken security posture.

Usage:
    boundaryctl config lint
    boundaryctl config lint --fix
    boundaryctl config diff old.conf new.conf

Severity Levels:
    CRITICAL - Blocks daemon startup (conflicting modes, invalid paths)
    HIGH     - Major security weakness (overly permissive rules)
    MEDIUM   - Potential issues (unreachable endpoints, deprecated options)
    LOW      - Style/best practice warnings
"""

import configparser
import logging
import os
import re
import stat
import socket
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Callable

logger = logging.getLogger(__name__)


class LintSeverity(Enum):
    """Severity levels for lint findings."""
    CRITICAL = "critical"  # Blocks startup
    HIGH = "high"          # Major security weakness
    MEDIUM = "medium"      # Potential issues
    LOW = "low"            # Style/best practice


class LintCategory(Enum):
    """Categories of lint findings."""
    SECURITY = "security"
    CONFIGURATION = "configuration"
    PERMISSION = "permission"
    NETWORK = "network"
    PATH = "path"
    DEPRECATED = "deprecated"
    CONSISTENCY = "consistency"


@dataclass
class LintFinding:
    """A single lint finding."""
    severity: LintSeverity
    category: LintCategory
    section: str
    key: Optional[str]
    message: str
    suggestion: Optional[str] = None
    auto_fixable: bool = False
    fix_value: Optional[str] = None

    def __str__(self) -> str:
        location = f"[{self.section}]"
        if self.key:
            location += f" {self.key}"
        sev_colors = {
            LintSeverity.CRITICAL: "\033[91m",  # Red
            LintSeverity.HIGH: "\033[93m",      # Yellow
            LintSeverity.MEDIUM: "\033[94m",    # Blue
            LintSeverity.LOW: "\033[90m",       # Gray
        }
        reset = "\033[0m"
        color = sev_colors.get(self.severity, "")
        return f"{color}[{self.severity.value.upper()}]{reset} {location}: {self.message}"


@dataclass
class LintResult:
    """Result of linting operation."""
    findings: List[LintFinding] = field(default_factory=list)
    config_path: str = ""
    is_valid: bool = True
    can_start: bool = True

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == LintSeverity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == LintSeverity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == LintSeverity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == LintSeverity.LOW)

    @property
    def fixable_count(self) -> int:
        return sum(1 for f in self.findings if f.auto_fixable)

    def summary(self) -> str:
        """Generate summary string."""
        if not self.findings:
            return "\033[92m✓ Configuration is valid\033[0m"

        parts = []
        if self.critical_count:
            parts.append(f"\033[91m{self.critical_count} critical\033[0m")
        if self.high_count:
            parts.append(f"\033[93m{self.high_count} high\033[0m")
        if self.medium_count:
            parts.append(f"\033[94m{self.medium_count} medium\033[0m")
        if self.low_count:
            parts.append(f"\033[90m{self.low_count} low\033[0m")

        summary = f"Found {len(self.findings)} issues: " + ", ".join(parts)

        if not self.can_start:
            summary += "\n\033[91m✗ Daemon will NOT start with this configuration\033[0m"
        elif self.high_count:
            summary += "\n\033[93m⚠ Configuration has security weaknesses\033[0m"

        if self.fixable_count:
            summary += f"\n\033[96mℹ {self.fixable_count} issues can be auto-fixed with --fix\033[0m"

        return summary


class ConfigLinter:
    """
    Validates Boundary Daemon configuration files.

    Checks for:
    - Security misconfigurations
    - Invalid values and paths
    - Permission issues
    - Deprecated options
    - Consistency between settings
    """

    # Valid boundary modes
    VALID_MODES = {'open', 'restricted', 'trusted', 'airgap', 'coldroom', 'lockdown'}

    # Deprecated configuration options
    DEPRECATED_OPTIONS = {
        ('daemon', 'legacy_mode'): 'Use initial_mode instead',
        ('security', 'allow_unsigned'): 'Removed in v2.0, all code is now signed',
    }

    # Required sections
    REQUIRED_SECTIONS = {'daemon', 'tripwires', 'ceremony', 'logging', 'security'}

    def __init__(self):
        self.validators: List[Callable[[configparser.ConfigParser, LintResult], None]] = [
            self._check_required_sections,
            self._check_daemon_section,
            self._check_tripwires_section,
            self._check_ceremony_section,
            self._check_logging_section,
            self._check_security_section,
            self._check_network_section,
            self._check_hardware_section,
            self._check_deprecated_options,
            self._check_cross_section_consistency,
            self._check_file_permissions,
        ]

    def lint(self, config_path: str) -> LintResult:
        """
        Lint a configuration file.

        Args:
            config_path: Path to the configuration file

        Returns:
            LintResult with all findings
        """
        result = LintResult(config_path=config_path)

        # Check file exists
        if not os.path.exists(config_path):
            result.findings.append(LintFinding(
                severity=LintSeverity.CRITICAL,
                category=LintCategory.PATH,
                section="file",
                key=None,
                message=f"Configuration file not found: {config_path}",
            ))
            result.is_valid = False
            result.can_start = False
            return result

        # Parse configuration
        config = configparser.ConfigParser()
        try:
            config.read(config_path)
        except configparser.Error as e:
            result.findings.append(LintFinding(
                severity=LintSeverity.CRITICAL,
                category=LintCategory.CONFIGURATION,
                section="file",
                key=None,
                message=f"Failed to parse configuration: {e}",
            ))
            result.is_valid = False
            result.can_start = False
            return result

        # Run all validators
        for validator in self.validators:
            try:
                validator(config, result)
            except Exception as e:
                logger.warning(f"Validator {validator.__name__} failed: {e}")

        # Determine if daemon can start
        result.can_start = result.critical_count == 0
        result.is_valid = len(result.findings) == 0

        return result

    def lint_and_fix(self, config_path: str, backup: bool = True) -> Tuple[LintResult, int]:
        """
        Lint and auto-fix configuration file.

        Args:
            config_path: Path to the configuration file
            backup: Create backup before fixing

        Returns:
            (LintResult, number_of_fixes_applied)
        """
        result = self.lint(config_path)

        fixable = [f for f in result.findings if f.auto_fixable and f.fix_value is not None]
        if not fixable:
            return result, 0

        # Create backup
        if backup:
            backup_path = f"{config_path}.bak"
            import shutil
            shutil.copy2(config_path, backup_path)
            logger.info(f"Created backup: {backup_path}")

        # Apply fixes
        config = configparser.ConfigParser()
        config.read(config_path)

        fixes_applied = 0
        for finding in fixable:
            if finding.section in config:
                if finding.key:
                    config.set(finding.section, finding.key, finding.fix_value)
                    fixes_applied += 1
                    logger.info(f"Fixed [{finding.section}] {finding.key} = {finding.fix_value}")

        # Write fixed config
        with open(config_path, 'w') as f:
            config.write(f)

        # Re-lint to update result
        return self.lint(config_path), fixes_applied

    def _check_required_sections(self, config: configparser.ConfigParser, result: LintResult):
        """Check that all required sections are present."""
        for section in self.REQUIRED_SECTIONS:
            if section not in config:
                result.findings.append(LintFinding(
                    severity=LintSeverity.HIGH,
                    category=LintCategory.CONFIGURATION,
                    section=section,
                    key=None,
                    message=f"Missing required section [{section}]",
                    suggestion=f"Add [{section}] section with default values",
                ))

    def _check_daemon_section(self, config: configparser.ConfigParser, result: LintResult):
        """Validate [daemon] section."""
        if 'daemon' not in config:
            return

        daemon = config['daemon']

        # Check initial_mode
        if 'initial_mode' in daemon:
            mode = daemon['initial_mode'].lower()
            if mode not in self.VALID_MODES:
                result.findings.append(LintFinding(
                    severity=LintSeverity.CRITICAL,
                    category=LintCategory.CONFIGURATION,
                    section="daemon",
                    key="initial_mode",
                    message=f"Invalid mode '{mode}'. Valid modes: {', '.join(self.VALID_MODES)}",
                ))
            elif mode == 'open':
                result.findings.append(LintFinding(
                    severity=LintSeverity.HIGH,
                    category=LintCategory.SECURITY,
                    section="daemon",
                    key="initial_mode",
                    message="Mode 'open' provides minimal security - use only for development",
                    suggestion="Consider 'trusted' for production environments",
                    auto_fixable=True,
                    fix_value="trusted",
                ))

        # Check log_dir
        if 'log_dir' in daemon:
            log_dir = daemon['log_dir']
            if not os.path.isabs(log_dir):
                result.findings.append(LintFinding(
                    severity=LintSeverity.MEDIUM,
                    category=LintCategory.PATH,
                    section="daemon",
                    key="log_dir",
                    message=f"Relative path '{log_dir}' - consider using absolute path",
                    suggestion="Use absolute path like /var/log/boundary-daemon",
                ))

        # Check socket_path
        if 'socket_path' in daemon:
            socket_path = daemon['socket_path']
            socket_dir = os.path.dirname(socket_path)
            if socket_dir and not os.path.exists(socket_dir):
                result.findings.append(LintFinding(
                    severity=LintSeverity.MEDIUM,
                    category=LintCategory.PATH,
                    section="daemon",
                    key="socket_path",
                    message=f"Socket directory does not exist: {socket_dir}",
                    suggestion="Directory will be created on daemon start",
                ))

        # Check poll_interval
        if 'poll_interval' in daemon:
            try:
                interval = float(daemon['poll_interval'])
                if interval < 0.1:
                    result.findings.append(LintFinding(
                        severity=LintSeverity.MEDIUM,
                        category=LintCategory.CONFIGURATION,
                        section="daemon",
                        key="poll_interval",
                        message=f"Poll interval {interval}s is very short - may cause high CPU usage",
                        suggestion="Use at least 0.5s for production",
                    ))
                elif interval > 60:
                    result.findings.append(LintFinding(
                        severity=LintSeverity.MEDIUM,
                        category=LintCategory.SECURITY,
                        section="daemon",
                        key="poll_interval",
                        message=f"Poll interval {interval}s is very long - may miss security events",
                        suggestion="Use at most 10s for responsive security",
                    ))
            except ValueError:
                result.findings.append(LintFinding(
                    severity=LintSeverity.CRITICAL,
                    category=LintCategory.CONFIGURATION,
                    section="daemon",
                    key="poll_interval",
                    message=f"Invalid poll_interval value: {daemon['poll_interval']}",
                ))

    def _check_tripwires_section(self, config: configparser.ConfigParser, result: LintResult):
        """Validate [tripwires] section."""
        if 'tripwires' not in config:
            return

        tripwires = config['tripwires']

        # Check enabled
        if 'enabled' in tripwires:
            if tripwires['enabled'].lower() == 'false':
                result.findings.append(LintFinding(
                    severity=LintSeverity.CRITICAL,
                    category=LintCategory.SECURITY,
                    section="tripwires",
                    key="enabled",
                    message="Tripwires are DISABLED - security monitoring is off",
                    suggestion="Set enabled = true for production",
                    auto_fixable=True,
                    fix_value="true",
                ))

        # Check auto_lockdown
        if 'auto_lockdown' in tripwires:
            if tripwires['auto_lockdown'].lower() == 'false':
                result.findings.append(LintFinding(
                    severity=LintSeverity.HIGH,
                    category=LintCategory.SECURITY,
                    section="tripwires",
                    key="auto_lockdown",
                    message="Auto-lockdown is disabled - violations won't trigger lockdown",
                    suggestion="Enable for fail-closed security",
                    auto_fixable=True,
                    fix_value="true",
                ))

    def _check_ceremony_section(self, config: configparser.ConfigParser, result: LintResult):
        """Validate [ceremony] section."""
        if 'ceremony' not in config:
            return

        ceremony = config['ceremony']

        # Check cooldown_seconds
        if 'cooldown_seconds' in ceremony:
            try:
                cooldown = int(ceremony['cooldown_seconds'])
                if cooldown < 10:
                    result.findings.append(LintFinding(
                        severity=LintSeverity.HIGH,
                        category=LintCategory.SECURITY,
                        section="ceremony",
                        key="cooldown_seconds",
                        message=f"Cooldown {cooldown}s is too short - reduces ceremony effectiveness",
                        suggestion="Use at least 30s to prevent rushed decisions",
                        auto_fixable=True,
                        fix_value="30",
                    ))
                elif cooldown > 300:
                    result.findings.append(LintFinding(
                        severity=LintSeverity.LOW,
                        category=LintCategory.CONFIGURATION,
                        section="ceremony",
                        key="cooldown_seconds",
                        message=f"Cooldown {cooldown}s is very long - may impede emergency response",
                    ))
            except ValueError:
                result.findings.append(LintFinding(
                    severity=LintSeverity.CRITICAL,
                    category=LintCategory.CONFIGURATION,
                    section="ceremony",
                    key="cooldown_seconds",
                    message=f"Invalid cooldown_seconds value: {ceremony['cooldown_seconds']}",
                ))

    def _check_logging_section(self, config: configparser.ConfigParser, result: LintResult):
        """Validate [logging] section."""
        if 'logging' not in config:
            return

        logging_config = config['logging']

        # Check event_log path
        if 'event_log' in logging_config:
            log_path = logging_config['event_log']
            log_dir = os.path.dirname(log_path)
            if log_dir and not os.path.exists(log_dir):
                result.findings.append(LintFinding(
                    severity=LintSeverity.MEDIUM,
                    category=LintCategory.PATH,
                    section="logging",
                    key="event_log",
                    message=f"Log directory does not exist: {log_dir}",
                ))

        # Check debug mode
        if 'debug' in logging_config:
            if logging_config['debug'].lower() == 'true':
                result.findings.append(LintFinding(
                    severity=LintSeverity.MEDIUM,
                    category=LintCategory.SECURITY,
                    section="logging",
                    key="debug",
                    message="Debug mode is enabled - may log sensitive information",
                    suggestion="Disable in production",
                    auto_fixable=True,
                    fix_value="false",
                ))

        # Check max_log_files
        if 'max_log_files' in logging_config:
            try:
                max_files = int(logging_config['max_log_files'])
                if max_files < 3:
                    result.findings.append(LintFinding(
                        severity=LintSeverity.LOW,
                        category=LintCategory.CONFIGURATION,
                        section="logging",
                        key="max_log_files",
                        message=f"Only {max_files} log files retained - limited audit history",
                        suggestion="Keep at least 10 for adequate audit trail",
                    ))
            except ValueError:
                pass

    def _check_security_section(self, config: configparser.ConfigParser, result: LintResult):
        """Validate [security] section."""
        if 'security' not in config:
            return

        security = config['security']

        # Check fail_closed
        if 'fail_closed' in security:
            if security['fail_closed'].lower() == 'false':
                result.findings.append(LintFinding(
                    severity=LintSeverity.CRITICAL,
                    category=LintCategory.SECURITY,
                    section="security",
                    key="fail_closed",
                    message="Fail-closed is DISABLED - system will fail open on errors",
                    suggestion="Enable for secure defaults",
                    auto_fixable=True,
                    fix_value="true",
                ))

        # Check max_clock_drift
        if 'max_clock_drift' in security:
            try:
                drift = int(security['max_clock_drift'])
                if drift > 600:
                    result.findings.append(LintFinding(
                        severity=LintSeverity.MEDIUM,
                        category=LintCategory.SECURITY,
                        section="security",
                        key="max_clock_drift",
                        message=f"Clock drift tolerance {drift}s is very high",
                        suggestion="Use 300s or less to detect time manipulation",
                    ))
            except ValueError:
                pass

    def _check_network_section(self, config: configparser.ConfigParser, result: LintResult):
        """Validate [network] section."""
        if 'network' not in config:
            return

        network = config['network']

        # Check trusted_interfaces
        if 'trusted_interfaces' in network:
            interfaces = network['trusted_interfaces']
            if not interfaces.strip():
                result.findings.append(LintFinding(
                    severity=LintSeverity.LOW,
                    category=LintCategory.NETWORK,
                    section="network",
                    key="trusted_interfaces",
                    message="No trusted interfaces defined",
                    suggestion="Add VPN interfaces like wg0, tun0",
                ))
            elif '*' in interfaces:
                result.findings.append(LintFinding(
                    severity=LintSeverity.HIGH,
                    category=LintCategory.SECURITY,
                    section="network",
                    key="trusted_interfaces",
                    message="Wildcard in trusted_interfaces trusts ALL interfaces",
                    suggestion="Explicitly list trusted VPN interfaces",
                ))

        # Check trusted_dns
        if 'trusted_dns' in network:
            dns_servers = network['trusted_dns'].split(',')
            for server in dns_servers:
                server = server.strip()
                if server:
                    # Validate IP address format
                    try:
                        socket.inet_aton(server)
                    except socket.error:
                        result.findings.append(LintFinding(
                            severity=LintSeverity.MEDIUM,
                            category=LintCategory.NETWORK,
                            section="network",
                            key="trusted_dns",
                            message=f"Invalid DNS server IP: {server}",
                        ))

    def _check_hardware_section(self, config: configparser.ConfigParser, result: LintResult):
        """Validate [hardware] section."""
        if 'hardware' not in config:
            return

        hardware = config['hardware']

        # Check block_usb_storage
        if 'block_usb_storage' in hardware:
            if hardware['block_usb_storage'].lower() == 'false':
                result.findings.append(LintFinding(
                    severity=LintSeverity.MEDIUM,
                    category=LintCategory.SECURITY,
                    section="hardware",
                    key="block_usb_storage",
                    message="USB storage blocking is disabled",
                    suggestion="Enable for data exfiltration protection",
                ))

        # Check whitelisted_usb_devices format
        if 'whitelisted_usb_devices' in hardware:
            devices = hardware['whitelisted_usb_devices']
            if devices.strip() and '*' in devices:
                result.findings.append(LintFinding(
                    severity=LintSeverity.CRITICAL,
                    category=LintCategory.SECURITY,
                    section="hardware",
                    key="whitelisted_usb_devices",
                    message="Wildcard in USB whitelist allows ALL devices",
                    suggestion="Remove wildcard and list specific device IDs",
                ))

    def _check_deprecated_options(self, config: configparser.ConfigParser, result: LintResult):
        """Check for deprecated configuration options."""
        for (section, key), message in self.DEPRECATED_OPTIONS.items():
            if section in config and key in config[section]:
                result.findings.append(LintFinding(
                    severity=LintSeverity.MEDIUM,
                    category=LintCategory.DEPRECATED,
                    section=section,
                    key=key,
                    message=f"Deprecated option: {message}",
                    suggestion="Remove this option",
                ))

    def _check_cross_section_consistency(self, config: configparser.ConfigParser, result: LintResult):
        """Check consistency between different sections."""
        # Check: If airgap mode requires TPM, ensure TPM is configured
        if 'daemon' in config and 'security' in config:
            initial_mode = config['daemon'].get('initial_mode', 'trusted').lower()
            require_tpm = config['security'].get('require_tpm_for_airgap', 'false').lower() == 'true'

            if initial_mode in ('airgap', 'coldroom') and not require_tpm:
                result.findings.append(LintFinding(
                    severity=LintSeverity.LOW,
                    category=LintCategory.CONSISTENCY,
                    section="security",
                    key="require_tpm_for_airgap",
                    message=f"High-security mode '{initial_mode}' without TPM requirement",
                    suggestion="Consider enabling require_tpm_for_airgap for hardware-backed security",
                ))

        # Check: If biometric required but ceremony section missing
        if 'ceremony' in config:
            require_bio = config['ceremony'].get('require_biometric', 'false').lower() == 'true'
            if require_bio:
                result.findings.append(LintFinding(
                    severity=LintSeverity.LOW,
                    category=LintCategory.CONSISTENCY,
                    section="ceremony",
                    key="require_biometric",
                    message="Biometric required - ensure fingerprint reader or camera is available",
                ))

    def _check_file_permissions(self, config: configparser.ConfigParser, result: LintResult):
        """Check file permissions on sensitive paths."""
        paths_to_check = []

        if 'logging' in config and 'event_log' in config['logging']:
            paths_to_check.append(('logging', 'event_log', config['logging']['event_log']))

        if 'daemon' in config and 'socket_path' in config['daemon']:
            socket_dir = os.path.dirname(config['daemon']['socket_path'])
            if socket_dir:
                paths_to_check.append(('daemon', 'socket_path', socket_dir))

        for section, key, path in paths_to_check:
            if os.path.exists(path):
                try:
                    st = os.stat(path)
                    mode = st.st_mode

                    # Check if world-writable
                    if mode & stat.S_IWOTH:
                        result.findings.append(LintFinding(
                            severity=LintSeverity.HIGH,
                            category=LintCategory.PERMISSION,
                            section=section,
                            key=key,
                            message=f"Path is world-writable: {path}",
                            suggestion="Remove world-write permission: chmod o-w",
                        ))

                    # Check if world-readable (for sensitive paths)
                    if mode & stat.S_IROTH and 'log' not in path.lower():
                        result.findings.append(LintFinding(
                            severity=LintSeverity.MEDIUM,
                            category=LintCategory.PERMISSION,
                            section=section,
                            key=key,
                            message=f"Sensitive path is world-readable: {path}",
                            suggestion="Consider restricting permissions",
                        ))
                except OSError:
                    pass


def lint_config(config_path: str, fix: bool = False, quiet: bool = False) -> int:
    """
    Lint configuration file and return exit code.

    Args:
        config_path: Path to configuration file
        fix: Auto-fix fixable issues
        quiet: Suppress output except errors

    Returns:
        0 if valid, 1 if has issues, 2 if critical issues
    """
    linter = ConfigLinter()

    if fix:
        result, fixes = linter.lint_and_fix(config_path)
        if not quiet and fixes:
            print(f"\033[92m✓ Applied {fixes} fixes\033[0m\n")
    else:
        result = linter.lint(config_path)

    # Print findings
    if not quiet:
        if result.findings:
            print(f"Linting {result.config_path}:\n")
            for finding in result.findings:
                print(f"  {finding}")
                if finding.suggestion:
                    print(f"    \033[90m→ {finding.suggestion}\033[0m")
            print()

        print(result.summary())

    # Return exit code
    if not result.can_start:
        return 2
    elif result.high_count > 0:
        return 1
    return 0


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Lint Boundary Daemon configuration")
    parser.add_argument("config", help="Path to configuration file")
    parser.add_argument("--fix", action="store_true", help="Auto-fix fixable issues")
    parser.add_argument("--quiet", "-q", action="store_true", help="Quiet mode")

    args = parser.parse_args()

    exit_code = lint_config(args.config, fix=args.fix, quiet=args.quiet)
    exit(exit_code)
