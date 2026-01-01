"""
Mandatory Access Control (MAC) Profile Generator

Generates SELinux and AppArmor profiles for the Boundary Daemon
and monitored processes. Provides process enforcement to complement
the daemon's detection capabilities.

Supported systems:
- SELinux (RHEL, Fedora, CentOS)
- AppArmor (Ubuntu, Debian, SUSE)

Usage:
    from daemon.enforcement.mac_profiles import (
        MACProfileGenerator,
        get_mac_generator,
    )

    gen = get_mac_generator()

    # Generate profile for daemon
    profile = gen.generate_daemon_profile()

    # Generate profile for monitored process
    profile = gen.generate_process_profile("/usr/bin/myapp", mode="RESTRICTED")

    # Check current MAC status
    status = gen.get_mac_status()
"""

import logging
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class MACSystem(Enum):
    """Available MAC systems."""
    SELINUX = "selinux"
    APPARMOR = "apparmor"
    NONE = "none"


class SELinuxMode(Enum):
    """SELinux enforcement modes."""
    ENFORCING = "enforcing"
    PERMISSIVE = "permissive"
    DISABLED = "disabled"


class AppArmorMode(Enum):
    """AppArmor profile modes."""
    ENFORCE = "enforce"
    COMPLAIN = "complain"
    UNCONFINED = "unconfined"


@dataclass
class ProfileConfig:
    """Configuration for MAC profiles."""
    # Daemon paths
    daemon_path: str = "/usr/local/bin/boundary-daemon"
    daemon_config_dir: str = "/etc/boundary-daemon"
    daemon_log_dir: str = "/var/log/boundary-daemon"
    daemon_run_dir: str = "/var/run/boundary-daemon"

    # Allowed capabilities
    allowed_caps: Set[str] = field(default_factory=lambda: {
        "net_admin",       # Network configuration
        "sys_ptrace",      # Process monitoring
        "audit_write",     # Audit logging
    })

    # Network access
    allow_network: bool = True
    allowed_ports: Set[int] = field(default_factory=lambda: {514, 6514})  # Syslog

    # File access patterns
    read_paths: Set[str] = field(default_factory=lambda: {
        "/etc/boundary-daemon/**",
        "/proc/**",
        "/sys/**",
    })

    write_paths: Set[str] = field(default_factory=lambda: {
        "/var/log/boundary-daemon/**",
        "/var/run/boundary-daemon/**",
    })


class MACProfileGenerator:
    """
    Generates MAC profiles for SELinux and AppArmor.

    Provides enforcement policies that confine the daemon and
    monitored processes according to boundary modes.
    """

    def __init__(
        self,
        config: Optional[ProfileConfig] = None,
        event_logger=None,
    ):
        self.config = config or ProfileConfig()
        self._event_logger = event_logger
        self._mac_system = self._detect_mac_system()

    def _detect_mac_system(self) -> MACSystem:
        """Detect which MAC system is available."""
        # Check SELinux
        if Path("/sys/fs/selinux").exists() or shutil.which("getenforce"):
            return MACSystem.SELINUX

        # Check AppArmor
        if Path("/sys/kernel/security/apparmor").exists() or shutil.which("apparmor_status"):
            return MACSystem.APPARMOR

        return MACSystem.NONE

    @property
    def mac_system(self) -> MACSystem:
        """Get detected MAC system."""
        return self._mac_system

    @property
    def is_available(self) -> bool:
        """Check if MAC is available."""
        return self._mac_system != MACSystem.NONE

    def get_mac_status(self) -> Dict[str, Any]:
        """Get current MAC system status."""
        status = {
            'system': self._mac_system.value,
            'available': self.is_available,
            'mode': 'unknown',
            'profiles_loaded': 0,
        }

        try:
            if self._mac_system == MACSystem.SELINUX:
                result = subprocess.run(["getenforce"], capture_output=True, text=True)
                if result.returncode == 0:
                    status['mode'] = result.stdout.strip().lower()

                result = subprocess.run(["seinfo", "-t"], capture_output=True, text=True)
                if result.returncode == 0:
                    status['profiles_loaded'] = len(result.stdout.strip().split('\n'))

            elif self._mac_system == MACSystem.APPARMOR:
                result = subprocess.run(["aa-status", "--json"], capture_output=True, text=True)
                if result.returncode == 0:
                    import json
                    data = json.loads(result.stdout)
                    status['mode'] = 'enforcing' if data.get('profiles', {}) else 'disabled'
                    status['profiles_loaded'] = len(data.get('profiles', {}))

        except Exception as e:
            status['error'] = str(e)

        return status

    def generate_daemon_profile(self) -> str:
        """Generate MAC profile for the daemon itself."""
        if self._mac_system == MACSystem.SELINUX:
            return self._generate_selinux_daemon_policy()
        elif self._mac_system == MACSystem.APPARMOR:
            return self._generate_apparmor_daemon_profile()
        else:
            return "# No MAC system detected"

    def _generate_selinux_daemon_policy(self) -> str:
        """Generate SELinux policy module for daemon."""
        policy = f'''
# SELinux Policy Module for Boundary Daemon
# Generated automatically - do not edit manually

policy_module(boundary_daemon, 1.0.0)

########################################
# Type Declarations
########################################

type boundary_daemon_t;
type boundary_daemon_exec_t;
type boundary_daemon_log_t;
type boundary_daemon_var_run_t;
type boundary_daemon_etc_t;

########################################
# Domain Transition
########################################

init_daemon_domain(boundary_daemon_t, boundary_daemon_exec_t)

########################################
# Permissions
########################################

# File contexts
files_type(boundary_daemon_log_t)
files_type(boundary_daemon_var_run_t)
files_type(boundary_daemon_etc_t)

# Allow daemon to read its config
allow boundary_daemon_t boundary_daemon_etc_t:dir list_dir_perms;
allow boundary_daemon_t boundary_daemon_etc_t:file read_file_perms;

# Allow daemon to write logs
allow boundary_daemon_t boundary_daemon_log_t:dir create_dir_perms;
allow boundary_daemon_t boundary_daemon_log_t:file create_file_perms;
logging_log_filetrans(boundary_daemon_t, boundary_daemon_log_t, {{ file dir }})

# Allow daemon to create runtime files
allow boundary_daemon_t boundary_daemon_var_run_t:dir create_dir_perms;
allow boundary_daemon_t boundary_daemon_var_run_t:file create_file_perms;
allow boundary_daemon_t boundary_daemon_var_run_t:sock_file create_file_perms;
files_pid_filetrans(boundary_daemon_t, boundary_daemon_var_run_t, {{ file dir sock_file }})

# Read /proc for process monitoring
kernel_read_system_state(boundary_daemon_t)
domain_read_all_domains_state(boundary_daemon_t)

# Read /sys for system monitoring
dev_read_sysfs(boundary_daemon_t)

# Network access for SIEM
{"sysadm_net_t network_port_t:tcp_socket {{ name_connect }};" if self.config.allow_network else ""}

# Capabilities
allow boundary_daemon_t self:capability {{ {" ".join(self.config.allowed_caps)} }};

# Unix socket for API
allow boundary_daemon_t self:unix_stream_socket create_stream_socket_perms;

########################################
# File Contexts
########################################

/usr/local/bin/boundary-daemon    --    gen_context(system_u:object_r:boundary_daemon_exec_t,s0)
/etc/boundary-daemon(/.*)?        gen_context(system_u:object_r:boundary_daemon_etc_t,s0)
/var/log/boundary-daemon(/.*)?    gen_context(system_u:object_r:boundary_daemon_log_t,s0)
/var/run/boundary-daemon(/.*)?    gen_context(system_u:object_r:boundary_daemon_var_run_t,s0)
'''
        return policy.strip()

    def _generate_apparmor_daemon_profile(self) -> str:
        """Generate AppArmor profile for daemon."""
        read_paths = "\n    ".join(f"{p} r," for p in self.config.read_paths)
        write_paths = "\n    ".join(f"{p} rw," for p in self.config.write_paths)
        caps = "\n    ".join(f"capability {c}," for c in self.config.allowed_caps)

        network = ""
        if self.config.allow_network:
            network = """
    # Network access for SIEM integration
    network inet stream,
    network inet dgram,
    network inet6 stream,
    network inet6 dgram,
"""

        profile = f'''#include <tunables/global>

# AppArmor Profile for Boundary Daemon
# Generated automatically - do not edit manually

profile boundary-daemon {self.config.daemon_path} flags=(attach_disconnected) {{
    #include <abstractions/base>
    #include <abstractions/python>

    # Capabilities
    {caps}

    # Execute self
    {self.config.daemon_path} mr,

    # Python interpreter
    /usr/bin/python3* ix,
    /usr/lib/python3*/** r,

    # Configuration
    {self.config.daemon_config_dir}/ r,
    {self.config.daemon_config_dir}/** r,

    # Logging
    {self.config.daemon_log_dir}/ rw,
    {self.config.daemon_log_dir}/** rw,

    # Runtime files
    {self.config.daemon_run_dir}/ rw,
    {self.config.daemon_run_dir}/** rw,

    # Process monitoring
    @{{PROC}}/@{{pid}}/stat r,
    @{{PROC}}/@{{pid}}/status r,
    @{{PROC}}/@{{pid}}/fd/ r,
    @{{PROC}}/sys/kernel/random/uuid r,
    @{{PROC}}/meminfo r,
    @{{PROC}}/loadavg r,
    @{{PROC}}/uptime r,

    # System monitoring
    /sys/class/** r,
    /sys/devices/** r,
    /sys/fs/** r,

    # Read paths
    {read_paths}

    # Write paths
    {write_paths}
{network}
    # Unix socket for API
    owner /var/run/boundary-daemon/*.sock rw,

    # Deny dangerous operations
    deny /etc/shadow r,
    deny /etc/passwd w,
    deny /boot/** rwx,
    deny /lib/modules/** w,
}}
'''
        return profile.strip()

    def generate_process_profile(
        self,
        process_path: str,
        mode: str = "RESTRICTED",
        name: Optional[str] = None,
    ) -> str:
        """
        Generate MAC profile for a monitored process.

        Args:
            process_path: Path to the executable
            mode: Boundary mode (affects restrictions)
            name: Profile name (defaults to process name)
        """
        if self._mac_system == MACSystem.APPARMOR:
            return self._generate_apparmor_process_profile(process_path, mode, name)
        else:
            return f"# SELinux process profiles require custom module - use audit2allow"

    def _generate_apparmor_process_profile(
        self,
        process_path: str,
        mode: str,
        name: Optional[str],
    ) -> str:
        """Generate AppArmor profile for monitored process."""
        mode_upper = mode.upper()
        profile_name = name or Path(process_path).name

        # Mode-specific restrictions
        if mode_upper == "AIRGAP":
            network = "    # AIRGAP: No network access\n    deny network,"
            file_access = """
    # AIRGAP: Minimal file access
    /usr/lib/** r,
    /lib/** r,
    deny /home/** rw,
    deny /tmp/** rw,
"""
        elif mode_upper == "RESTRICTED":
            network = """
    # RESTRICTED: Limited network
    network inet stream,
    deny network inet dgram,
"""
            file_access = """
    # RESTRICTED: Read-only home
    owner @{HOME}/** r,
    deny @{HOME}/** w,
    /tmp/** rw,
"""
        else:  # OPEN
            network = """
    # OPEN: Full network
    network inet stream,
    network inet dgram,
"""
            file_access = """
    # OPEN: Standard file access
    owner @{HOME}/** rw,
    /tmp/** rw,
"""

        profile = f'''#include <tunables/global>

# AppArmor Profile for: {profile_name}
# Mode: {mode}
# Generated by Boundary Daemon

profile {profile_name} {process_path} flags=(attach_disconnected) {{
    #include <abstractions/base>

    # Execute self
    {process_path} mr,

{network}

{file_access}

    # Deny dangerous operations
    deny /etc/shadow r,
    deny /etc/passwd w,
    deny /boot/** rwx,
    deny capability sys_admin,
    deny capability sys_module,
    deny capability sys_rawio,
}}
'''
        return profile.strip()

    def install_profile(self, profile: str, name: str) -> Tuple[bool, str]:
        """
        Install a MAC profile.

        Requires root privileges.
        """
        if os.geteuid() != 0:
            return False, "Root privileges required"

        try:
            if self._mac_system == MACSystem.APPARMOR:
                profile_path = Path(f"/etc/apparmor.d/{name}")
                profile_path.write_text(profile)

                result = subprocess.run(
                    ["apparmor_parser", "-r", str(profile_path)],
                    capture_output=True,
                    text=True,
                )

                if result.returncode != 0:
                    return False, f"Failed to load profile: {result.stderr}"

                return True, f"Profile installed: {profile_path}"

            elif self._mac_system == MACSystem.SELINUX:
                # SELinux requires compilation
                te_path = Path(f"/tmp/{name}.te")
                te_path.write_text(profile)

                # Compile module
                subprocess.run(["checkmodule", "-M", "-m", "-o", f"/tmp/{name}.mod", str(te_path)])
                subprocess.run(["semodule_package", "-o", f"/tmp/{name}.pp", "-m", f"/tmp/{name}.mod"])
                result = subprocess.run(["semodule", "-i", f"/tmp/{name}.pp"], capture_output=True, text=True)

                if result.returncode != 0:
                    return False, f"Failed to install SELinux module: {result.stderr}"

                return True, f"SELinux module installed: {name}"

            else:
                return False, "No MAC system available"

        except Exception as e:
            return False, str(e)

    def set_process_mode(self, pid: int, mode: str) -> Tuple[bool, str]:
        """
        Set MAC mode for a running process.

        Args:
            pid: Process ID
            mode: enforce, complain, or unconfined
        """
        if self._mac_system != MACSystem.APPARMOR:
            return False, "Only supported for AppArmor"

        try:
            if mode == "enforce":
                cmd = ["aa-enforce"]
            elif mode == "complain":
                cmd = ["aa-complain"]
            else:
                return False, f"Invalid mode: {mode}"

            # Get process executable
            exe_path = Path(f"/proc/{pid}/exe").resolve()

            result = subprocess.run(
                cmd + [str(exe_path)],
                capture_output=True,
                text=True,
            )

            if result.returncode != 0:
                return False, result.stderr

            return True, f"Set {mode} mode for PID {pid}"

        except Exception as e:
            return False, str(e)


# Global instance
_mac_generator: Optional[MACProfileGenerator] = None


def get_mac_generator(
    config: Optional[ProfileConfig] = None,
    event_logger=None,
) -> MACProfileGenerator:
    """Get or create the global MAC profile generator."""
    global _mac_generator
    if _mac_generator is None:
        _mac_generator = MACProfileGenerator(config, event_logger)
    return _mac_generator


__all__ = [
    'MACProfileGenerator',
    'ProfileConfig',
    'MACSystem',
    'SELinuxMode',
    'AppArmorMode',
    'get_mac_generator',
]
