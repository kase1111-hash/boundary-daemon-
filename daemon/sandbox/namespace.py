"""
Linux Namespace Isolation for Boundary Daemon Sandbox

Provides process isolation using Linux namespaces:
- PID namespace: Isolated process tree
- Mount namespace: Private filesystem view
- Network namespace: Isolated network stack
- User namespace: UID/GID mapping (unprivileged containers)
- UTS namespace: Isolated hostname
- IPC namespace: Isolated System V IPC

This module uses unshare(2) and clone(2) via ctypes for portability.
Falls back gracefully on systems without namespace support.
"""

import ctypes
import ctypes.util
import logging
import os
import signal
import subprocess
import tempfile
import shutil
from dataclasses import dataclass, field
from enum import IntFlag
from pathlib import Path
from typing import Dict, List, Optional, Callable, Any

logger = logging.getLogger(__name__)

# Linux namespace flags from sched.h
CLONE_NEWNS = 0x00020000    # Mount namespace
CLONE_NEWUTS = 0x04000000   # UTS namespace (hostname)
CLONE_NEWIPC = 0x08000000   # IPC namespace
CLONE_NEWUSER = 0x10000000  # User namespace
CLONE_NEWPID = 0x20000000   # PID namespace
CLONE_NEWNET = 0x40000000   # Network namespace
CLONE_NEWCGROUP = 0x02000000  # Cgroup namespace


class NamespaceFlags(IntFlag):
    """Namespace isolation flags."""
    NONE = 0
    MOUNT = CLONE_NEWNS
    UTS = CLONE_NEWUTS
    IPC = CLONE_NEWIPC
    USER = CLONE_NEWUSER
    PID = CLONE_NEWPID
    NET = CLONE_NEWNET
    CGROUP = CLONE_NEWCGROUP

    # Common combinations
    MINIMAL = MOUNT | PID
    STANDARD = MOUNT | PID | IPC | UTS
    FULL = MOUNT | PID | IPC | UTS | NET
    MAXIMUM = MOUNT | PID | IPC | UTS | NET | USER | CGROUP


@dataclass
class NamespaceConfig:
    """Configuration for namespace isolation."""
    flags: NamespaceFlags = NamespaceFlags.STANDARD

    # Mount namespace options
    readonly_root: bool = False
    private_tmp: bool = True
    private_dev: bool = True
    bind_mounts: Dict[str, str] = field(default_factory=dict)  # host_path -> container_path
    readonly_mounts: List[str] = field(default_factory=list)

    # Network namespace options
    enable_loopback: bool = True
    create_veth: bool = False
    veth_name: str = "veth0"

    # User namespace options
    uid_map: Optional[str] = None  # e.g., "0 1000 1" (inside outside count)
    gid_map: Optional[str] = None
    setgroups_deny: bool = True

    # UTS namespace options
    hostname: Optional[str] = "sandbox"

    # Process options
    new_session: bool = True
    chdir: Optional[str] = None

    # Filesystem root
    root_path: Optional[str] = None  # pivot_root to this path


class NamespaceError(Exception):
    """Error during namespace operations."""
    pass


class NamespaceManager:
    """
    Manages Linux namespace operations.

    Provides methods to:
    - Unshare current process from namespaces
    - Create child processes in new namespaces
    - Set up namespace-specific configuration

    Usage:
        manager = NamespaceManager()

        # Check capabilities
        if manager.can_create_namespaces():
            # Create isolated process
            proc = manager.create_isolated_process(
                command=["python3", "script.py"],
                config=NamespaceConfig(flags=NamespaceFlags.STANDARD),
            )
            proc.wait()
    """

    def __init__(self):
        self._libc = self._load_libc()
        self._capabilities = self._detect_capabilities()

    def _load_libc(self) -> Optional[ctypes.CDLL]:
        """Load libc for namespace syscalls."""
        try:
            libc_name = ctypes.util.find_library('c')
            if libc_name:
                return ctypes.CDLL(libc_name, use_errno=True)
        except Exception as e:
            logger.warning(f"Could not load libc: {e}")
        return None

    def _detect_capabilities(self) -> Dict[str, bool]:
        """Detect namespace capabilities."""
        caps = {
            'namespaces': False,
            'user_ns': False,
            'unprivileged_user_ns': False,
            'privileged': os.geteuid() == 0,
        }

        # Check if we're on Linux
        if os.name != 'posix':
            return caps

        # Check for namespace support
        try:
            # Check if unshare exists in libc
            if self._libc and hasattr(self._libc, 'unshare'):
                caps['namespaces'] = True

            # Check for user namespace support
            if Path('/proc/self/ns/user').exists():
                caps['user_ns'] = True

            # Check for unprivileged user namespaces
            try:
                with open('/proc/sys/kernel/unprivileged_userns_clone') as f:
                    caps['unprivileged_user_ns'] = f.read().strip() == '1'
            except FileNotFoundError:
                # Default is usually enabled if file doesn't exist
                caps['unprivileged_user_ns'] = caps['user_ns']
            except PermissionError:
                pass

        except Exception as e:
            logger.debug(f"Error detecting capabilities: {e}")

        return caps

    def can_create_namespaces(self) -> bool:
        """Check if we can create namespaces."""
        return self._capabilities.get('namespaces', False)

    def can_use_user_namespace(self) -> bool:
        """Check if we can use user namespaces (for unprivileged containers)."""
        if self._capabilities.get('privileged'):
            return True
        return self._capabilities.get('unprivileged_user_ns', False)

    def get_capabilities(self) -> Dict[str, bool]:
        """Get detected capabilities."""
        return self._capabilities.copy()

    def _unshare(self, flags: int) -> bool:
        """Call unshare(2) syscall."""
        if not self._libc:
            return False

        try:
            result = self._libc.unshare(flags)
            if result != 0:
                errno = ctypes.get_errno()
                logger.error(f"unshare failed with errno {errno}")
                return False
            return True
        except Exception as e:
            logger.error(f"unshare exception: {e}")
            return False

    def _write_id_map(self, pid: int, map_type: str, mapping: str) -> bool:
        """Write UID/GID mapping for user namespace."""
        try:
            map_file = Path(f'/proc/{pid}/{map_type}')
            map_file.write_text(mapping)
            return True
        except Exception as e:
            logger.error(f"Failed to write {map_type}: {e}")
            return False

    def _setup_mount_namespace(self, config: NamespaceConfig) -> None:
        """Set up mount namespace (called after unshare)."""
        try:
            # Make all mounts private (don't propagate to host)
            subprocess.run(
                ['mount', '--make-rprivate', '/'],
                check=False,
                capture_output=True,
            )

            # Set up private /tmp
            if config.private_tmp:
                tmp_dir = tempfile.mkdtemp(prefix='sandbox_tmp_')
                subprocess.run(
                    ['mount', '--bind', tmp_dir, '/tmp'],
                    check=False,
                    capture_output=True,
                )

            # Set up minimal /dev
            if config.private_dev:
                self._setup_minimal_dev()

            # Apply bind mounts
            for host_path, container_path in config.bind_mounts.items():
                Path(container_path).mkdir(parents=True, exist_ok=True)
                subprocess.run(
                    ['mount', '--bind', host_path, container_path],
                    check=False,
                    capture_output=True,
                )

            # Make specified paths readonly
            for path in config.readonly_mounts:
                subprocess.run(
                    ['mount', '-o', 'remount,ro', path],
                    check=False,
                    capture_output=True,
                )

            # Make root readonly if requested
            if config.readonly_root:
                subprocess.run(
                    ['mount', '-o', 'remount,ro', '/'],
                    check=False,
                    capture_output=True,
                )

        except Exception as e:
            logger.error(f"Failed to setup mount namespace: {e}")

    def _setup_minimal_dev(self) -> None:
        """Create minimal /dev with only essential devices."""
        try:
            dev_dir = tempfile.mkdtemp(prefix='sandbox_dev_')

            # Create essential device nodes (requires CAP_MKNOD or be root)
            essential = [
                ('null', 'c', 1, 3),
                ('zero', 'c', 1, 5),
                ('random', 'c', 1, 8),
                ('urandom', 'c', 1, 9),
            ]

            for name, dtype, major, minor in essential:
                path = Path(dev_dir) / name
                try:
                    # Try to create device node
                    mode = 0o666
                    if dtype == 'c':
                        os.mknod(str(path), mode | 0o020000, os.makedev(major, minor))
                except (OSError, PermissionError):
                    # Fall back to bind mount from host
                    try:
                        path.touch()
                        subprocess.run(
                            ['mount', '--bind', f'/dev/{name}', str(path)],
                            check=False,
                            capture_output=True,
                        )
                    except Exception:
                        pass

            # Create symlinks
            for link, target in [('fd', '/proc/self/fd'), ('stdin', 'fd/0'),
                                  ('stdout', 'fd/1'), ('stderr', 'fd/2')]:
                try:
                    (Path(dev_dir) / link).symlink_to(target)
                except Exception:
                    pass

            # Mount over /dev
            subprocess.run(
                ['mount', '--bind', dev_dir, '/dev'],
                check=False,
                capture_output=True,
            )

        except Exception as e:
            logger.debug(f"Could not setup minimal /dev: {e}")

    def _setup_network_namespace(self, config: NamespaceConfig) -> None:
        """Set up network namespace."""
        try:
            if config.enable_loopback:
                # Bring up loopback interface
                subprocess.run(
                    ['ip', 'link', 'set', 'lo', 'up'],
                    check=False,
                    capture_output=True,
                )
        except Exception as e:
            logger.debug(f"Could not setup network namespace: {e}")

    def _setup_uts_namespace(self, config: NamespaceConfig) -> None:
        """Set up UTS namespace (hostname)."""
        try:
            if config.hostname:
                # Set hostname via sethostname(2) or subprocess
                subprocess.run(
                    ['hostname', config.hostname],
                    check=False,
                    capture_output=True,
                )
        except Exception as e:
            logger.debug(f"Could not set hostname: {e}")

    def create_isolated_process(
        self,
        command: List[str],
        config: Optional[NamespaceConfig] = None,
        env: Optional[Dict[str, str]] = None,
        stdin: Optional[int] = None,
        stdout: Optional[int] = None,
        stderr: Optional[int] = None,
    ) -> 'IsolatedProcess':
        """
        Create a process isolated in namespaces.

        Args:
            command: Command and arguments to execute
            config: Namespace configuration
            env: Environment variables
            stdin/stdout/stderr: File descriptors

        Returns:
            IsolatedProcess wrapper
        """
        config = config or NamespaceConfig()

        # Determine which unshare flags we can use
        flags = int(config.flags)

        # If not root and user namespaces available, prepend user namespace
        if not self._capabilities['privileged'] and self.can_use_user_namespace():
            flags |= CLONE_NEWUSER

        # Build unshare command
        unshare_cmd = ['unshare']

        flag_map = [
            (CLONE_NEWNS, '--mount'),
            (CLONE_NEWPID, '--pid', '--fork'),
            (CLONE_NEWIPC, '--ipc'),
            (CLONE_NEWUTS, '--uts'),
            (CLONE_NEWNET, '--net'),
            (CLONE_NEWUSER, '--user'),
            (CLONE_NEWCGROUP, '--cgroup'),
        ]

        for flag_val, *args in flag_map:
            if flags & flag_val:
                unshare_cmd.extend(args)

        # Add mount-proc for PID namespace
        if flags & CLONE_NEWPID:
            unshare_cmd.append('--mount-proc')

        # Add user namespace mappings
        if flags & CLONE_NEWUSER:
            if config.uid_map:
                unshare_cmd.extend(['--map-user', config.uid_map.split()[1]])
            else:
                unshare_cmd.append('--map-root-user')

        # Add the actual command
        unshare_cmd.extend(command)

        # Create process
        process = subprocess.Popen(
            unshare_cmd,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            env=env,
            start_new_session=config.new_session,
            cwd=config.chdir,
        )

        return IsolatedProcess(process, config)

    def run_in_namespace(
        self,
        function: Callable[[], Any],
        config: Optional[NamespaceConfig] = None,
    ) -> Optional[Any]:
        """
        Fork and run a function in isolated namespaces.

        This is useful for Python code that needs to run isolated.
        Uses fork() so only works on Unix-like systems.

        Args:
            function: Function to execute in isolated namespace
            config: Namespace configuration

        Returns:
            Return value from function (via pickle through pipe)
        """
        config = config or NamespaceConfig()

        if not self.can_create_namespaces():
            logger.warning("Namespaces not available, running without isolation")
            return function()

        import pickle

        # Create pipe for result
        read_fd, write_fd = os.pipe()

        pid = os.fork()

        if pid == 0:
            # Child process
            os.close(read_fd)

            try:
                # Unshare namespaces
                flags = int(config.flags)
                if not self._unshare(flags):
                    os._exit(1)

                # Set up namespaces
                if flags & CLONE_NEWNS:
                    self._setup_mount_namespace(config)
                if flags & CLONE_NEWNET:
                    self._setup_network_namespace(config)
                if flags & CLONE_NEWUTS:
                    self._setup_uts_namespace(config)

                # Run function
                result = function()

                # Send result back
                os.write(write_fd, pickle.dumps(result))
                os.close(write_fd)
                os._exit(0)

            except Exception as e:
                logger.error(f"Error in isolated process: {e}")
                os._exit(1)

        else:
            # Parent process
            os.close(write_fd)

            # Wait for child
            _, status = os.waitpid(pid, 0)

            # Read result
            result_data = b''
            while True:
                chunk = os.read(read_fd, 4096)
                if not chunk:
                    break
                result_data += chunk
            os.close(read_fd)

            if os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0 and result_data:
                return pickle.loads(result_data)

            return None


class IsolatedProcess:
    """
    Wrapper for a process running in isolated namespaces.

    Provides subprocess.Popen-like interface with additional
    namespace-aware functionality.
    """

    def __init__(
        self,
        process: subprocess.Popen,
        config: NamespaceConfig,
    ):
        self._process = process
        self._config = config

    @property
    def pid(self) -> int:
        """Get process ID."""
        return self._process.pid

    @property
    def returncode(self) -> Optional[int]:
        """Get return code (None if still running)."""
        return self._process.returncode

    def poll(self) -> Optional[int]:
        """Check if process has terminated."""
        return self._process.poll()

    def wait(self, timeout: Optional[float] = None) -> int:
        """Wait for process to terminate."""
        return self._process.wait(timeout=timeout)

    def terminate(self) -> None:
        """Send SIGTERM to process."""
        self._process.terminate()

    def kill(self) -> None:
        """Send SIGKILL to process."""
        self._process.kill()

    def communicate(
        self,
        input: Optional[bytes] = None,
        timeout: Optional[float] = None,
    ) -> tuple:
        """Interact with process."""
        return self._process.communicate(input=input, timeout=timeout)

    @property
    def stdin(self):
        return self._process.stdin

    @property
    def stdout(self):
        return self._process.stdout

    @property
    def stderr(self):
        return self._process.stderr

    def get_namespace_path(self, ns_type: str) -> Optional[Path]:
        """
        Get path to process's namespace.

        Args:
            ns_type: Namespace type (mnt, pid, net, user, ipc, uts, cgroup)

        Returns:
            Path to namespace file or None
        """
        path = Path(f'/proc/{self.pid}/ns/{ns_type}')
        return path if path.exists() else None

    def get_cgroup_path(self) -> Optional[Path]:
        """Get path to process's cgroup."""
        try:
            cgroup_file = Path(f'/proc/{self.pid}/cgroup')
            if cgroup_file.exists():
                content = cgroup_file.read_text()
                for line in content.strip().split('\n'):
                    parts = line.split(':')
                    if len(parts) >= 3:
                        return Path(f'/sys/fs/cgroup{parts[2]}')
        except Exception:
            pass
        return None


if __name__ == '__main__':
    print("Testing Linux Namespace Isolation...")

    manager = NamespaceManager()

    print(f"\nCapabilities: {manager.get_capabilities()}")
    print(f"Can create namespaces: {manager.can_create_namespaces()}")
    print(f"Can use user namespace: {manager.can_use_user_namespace()}")

    if manager.can_create_namespaces():
        print("\nCreating isolated process...")

        config = NamespaceConfig(
            flags=NamespaceFlags.MINIMAL,
            hostname="test-sandbox",
        )

        proc = manager.create_isolated_process(
            command=['sh', '-c', 'echo "PID: $$"; hostname; id; ls /proc'],
            config=config,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        stdout, stderr = proc.communicate(timeout=10)
        print(f"\nOutput:\n{stdout.decode()}")
        if stderr:
            print(f"Stderr:\n{stderr.decode()}")
        print(f"Exit code: {proc.returncode}")
    else:
        print("\nNamespace creation not available on this system")
        print("(Requires Linux kernel 3.8+ and appropriate permissions)")

    print("\nNamespace isolation test complete.")
