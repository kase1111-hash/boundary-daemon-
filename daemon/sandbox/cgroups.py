"""
Cgroups v2 Resource Limits for Boundary Daemon Sandbox

Provides process resource control using Linux cgroups v2:
- CPU limits (quota, shares, max usage)
- Memory limits (max, swap, high watermark)
- I/O limits (bandwidth, IOPS)
- PID limits (max processes)
- Device access control

Cgroups v2 (unified hierarchy) is the modern cgroup interface.
Falls back to legacy cgroups v1 if v2 is not available.

Note: Requires appropriate permissions (root or delegated cgroups).
"""

import logging
import os
import shutil
import signal
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# Default cgroup v2 mount point
CGROUP_V2_PATH = Path('/sys/fs/cgroup')

# Cgroup controllers
CGROUP_CONTROLLERS = ['cpu', 'cpuset', 'io', 'memory', 'pids']


@dataclass
class CgroupLimits:
    """Resource limits for a cgroup."""

    # CPU limits
    cpu_quota_us: Optional[int] = None  # Microseconds per period
    cpu_period_us: int = 100000  # Period in microseconds (default 100ms)
    cpu_max_cores: Optional[float] = None  # Max CPU cores (e.g., 1.5 = 150%)
    cpu_weight: int = 100  # Relative weight (1-10000, default 100)

    # Memory limits
    memory_max_bytes: Optional[int] = None  # Hard limit
    memory_high_bytes: Optional[int] = None  # Soft limit (triggers reclaim)
    memory_swap_max_bytes: Optional[int] = None  # Swap limit (0 = no swap)
    memory_oom_kill: bool = True  # Kill on OOM or pause

    # I/O limits (per device, format: "major:minor rbps wbps riops wiops")
    io_max: List[str] = field(default_factory=list)  # ["8:0 rbps=10485760"]

    # PID limits
    pids_max: Optional[int] = None  # Maximum number of processes

    # CPU affinity
    cpuset_cpus: Optional[str] = None  # e.g., "0-3" or "0,2"
    cpuset_mems: Optional[str] = None  # NUMA nodes

    @classmethod
    def minimal(cls) -> 'CgroupLimits':
        """Minimal limits for low-resource sandboxes."""
        return cls(
            cpu_max_cores=0.5,
            memory_max_bytes=256 * 1024 * 1024,  # 256 MB
            memory_swap_max_bytes=0,  # No swap
            pids_max=100,
        )

    @classmethod
    def standard(cls) -> 'CgroupLimits':
        """Standard limits for typical sandboxes."""
        return cls(
            cpu_max_cores=2.0,
            memory_max_bytes=1024 * 1024 * 1024,  # 1 GB
            memory_high_bytes=768 * 1024 * 1024,  # 768 MB soft limit
            memory_swap_max_bytes=256 * 1024 * 1024,  # 256 MB swap
            pids_max=500,
        )

    @classmethod
    def unrestricted(cls) -> 'CgroupLimits':
        """Unrestricted limits (for monitoring only)."""
        return cls()

    @classmethod
    def for_boundary_mode(cls, mode: int) -> 'CgroupLimits':
        """
        Get appropriate limits for a boundary mode.

        Args:
            mode: Boundary mode (0=OPEN to 5=LOCKDOWN)
        """
        if mode >= 5:  # LOCKDOWN
            return cls(
                cpu_max_cores=0.1,
                memory_max_bytes=64 * 1024 * 1024,  # 64 MB
                memory_swap_max_bytes=0,
                pids_max=10,
            )
        elif mode >= 4:  # COLDROOM
            return cls.minimal()
        elif mode >= 3:  # AIRGAP
            return cls(
                cpu_max_cores=1.0,
                memory_max_bytes=512 * 1024 * 1024,  # 512 MB
                memory_swap_max_bytes=0,
                pids_max=200,
            )
        elif mode >= 2:  # TRUSTED
            return cls.standard()
        elif mode >= 1:  # RESTRICTED
            return cls.standard()
        else:  # OPEN
            return cls.unrestricted()


@dataclass
class ResourceUsage:
    """Current resource usage of a cgroup."""
    cpu_usage_us: int = 0  # Total CPU time in microseconds
    cpu_user_us: int = 0
    cpu_system_us: int = 0
    memory_current_bytes: int = 0
    memory_peak_bytes: int = 0
    memory_swap_bytes: int = 0
    io_read_bytes: int = 0
    io_write_bytes: int = 0
    pids_current: int = 0
    pids_peak: int = 0
    oom_kills: int = 0

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            'cpu': {
                'total_us': self.cpu_usage_us,
                'user_us': self.cpu_user_us,
                'system_us': self.cpu_system_us,
            },
            'memory': {
                'current_bytes': self.memory_current_bytes,
                'peak_bytes': self.memory_peak_bytes,
                'swap_bytes': self.memory_swap_bytes,
            },
            'io': {
                'read_bytes': self.io_read_bytes,
                'write_bytes': self.io_write_bytes,
            },
            'pids': {
                'current': self.pids_current,
                'peak': self.pids_peak,
            },
            'oom_kills': self.oom_kills,
        }


class CgroupError(Exception):
    """Error during cgroup operations."""
    pass


class CgroupManager:
    """
    Manages cgroup v2 resource limits.

    Provides methods to:
    - Create and delete cgroups
    - Set resource limits
    - Move processes to cgroups
    - Monitor resource usage

    Usage:
        manager = CgroupManager()

        # Create a cgroup for the sandbox
        cgroup = manager.create_cgroup("sandbox-1")

        # Set resource limits
        manager.set_limits(cgroup, CgroupLimits.standard())

        # Move a process to the cgroup
        manager.add_process(cgroup, pid)

        # Monitor usage
        usage = manager.get_usage(cgroup)
        print(f"Memory: {usage.memory_current_bytes / 1024 / 1024:.1f} MB")

        # Cleanup
        manager.delete_cgroup(cgroup)
    """

    def __init__(
        self,
        base_path: Optional[Path] = None,
        cgroup_name: str = "boundary-daemon",
    ):
        self._base_path = base_path or CGROUP_V2_PATH
        self._cgroup_name = cgroup_name
        self._capabilities = self._detect_capabilities()
        self._created_cgroups: Set[Path] = set()

    def _detect_capabilities(self) -> Dict[str, bool]:
        """Detect cgroup capabilities."""
        caps = {
            'cgroups_v2': False,
            'cgroups_v1': False,
            'can_create': False,
            'controllers': [],
        }

        try:
            # Check for cgroups v2
            if self._base_path.exists():
                # Check for unified hierarchy (cgroups v2)
                cgroup_type = self._base_path / 'cgroup.type'
                controllers = self._base_path / 'cgroup.controllers'

                if controllers.exists():
                    caps['cgroups_v2'] = True
                    caps['controllers'] = controllers.read_text().strip().split()

            # Check if we can create cgroups
            test_path = self._base_path / 'boundary-daemon-test'
            try:
                test_path.mkdir(exist_ok=True)
                test_path.rmdir()
                caps['can_create'] = True
            except (PermissionError, OSError):
                # Try user cgroup if available
                user_cgroup = self._find_user_cgroup()
                if user_cgroup:
                    self._base_path = user_cgroup
                    try:
                        test_path = user_cgroup / 'boundary-daemon-test'
                        test_path.mkdir(exist_ok=True)
                        test_path.rmdir()
                        caps['can_create'] = True
                    except (PermissionError, OSError):
                        pass

        except Exception as e:
            logger.debug(f"Error detecting cgroup capabilities: {e}")

        return caps

    def _find_user_cgroup(self) -> Optional[Path]:
        """Find the user's delegated cgroup (for rootless operation)."""
        try:
            # Check /proc/self/cgroup for our cgroup
            cgroup_file = Path('/proc/self/cgroup')
            if cgroup_file.exists():
                content = cgroup_file.read_text()
                for line in content.strip().split('\n'):
                    parts = line.split(':')
                    if len(parts) >= 3 and parts[0] == '0':
                        # cgroups v2 entry
                        cgroup_path = self._base_path / parts[2].lstrip('/')
                        if cgroup_path.exists():
                            return cgroup_path
        except Exception:
            pass
        return None

    def get_capabilities(self) -> Dict[str, bool]:
        """Get detected capabilities."""
        return self._capabilities.copy()

    def can_manage_cgroups(self) -> bool:
        """Check if we can manage cgroups."""
        return (
            self._capabilities.get('cgroups_v2', False) and
            self._capabilities.get('can_create', False)
        )

    def create_cgroup(self, name: str) -> Path:
        """
        Create a new cgroup.

        Args:
            name: Name for the cgroup

        Returns:
            Path to the created cgroup
        """
        cgroup_path = self._base_path / self._cgroup_name / name

        try:
            cgroup_path.mkdir(parents=True, exist_ok=True)
            self._created_cgroups.add(cgroup_path)

            # Enable controllers if we can
            self._enable_controllers(cgroup_path.parent)

            logger.debug(f"Created cgroup: {cgroup_path}")
            return cgroup_path

        except Exception as e:
            raise CgroupError(f"Failed to create cgroup: {e}")

    def _enable_controllers(self, cgroup_path: Path) -> None:
        """Enable controllers for a cgroup."""
        try:
            subtree_control = cgroup_path / 'cgroup.subtree_control'
            if subtree_control.exists():
                available = (cgroup_path / 'cgroup.controllers').read_text().strip().split()
                to_enable = [c for c in CGROUP_CONTROLLERS if c in available]

                if to_enable:
                    content = ' '.join(f'+{c}' for c in to_enable)
                    subtree_control.write_text(content)
        except Exception as e:
            logger.debug(f"Could not enable controllers: {e}")

    def delete_cgroup(self, cgroup_path: Path) -> bool:
        """
        Delete a cgroup.

        Note: All processes must be moved out first.

        Args:
            cgroup_path: Path to the cgroup

        Returns:
            True if deleted successfully
        """
        try:
            # Kill any remaining processes
            self._kill_processes(cgroup_path)

            # Wait for processes to exit
            for _ in range(10):
                procs = self.get_processes(cgroup_path)
                if not procs:
                    break
                time.sleep(0.1)

            # Delete cgroup
            if cgroup_path.exists():
                cgroup_path.rmdir()

            self._created_cgroups.discard(cgroup_path)
            logger.debug(f"Deleted cgroup: {cgroup_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete cgroup: {e}")
            return False

    def set_limits(self, cgroup_path: Path, limits: CgroupLimits) -> None:
        """
        Set resource limits for a cgroup.

        Args:
            cgroup_path: Path to the cgroup
            limits: Resource limits to apply
        """
        try:
            # CPU limits
            if limits.cpu_quota_us is not None or limits.cpu_max_cores is not None:
                if limits.cpu_max_cores is not None:
                    # Convert cores to quota
                    quota = int(limits.cpu_max_cores * limits.cpu_period_us)
                else:
                    quota = limits.cpu_quota_us

                cpu_max = cgroup_path / 'cpu.max'
                if cpu_max.exists():
                    cpu_max.write_text(f"{quota} {limits.cpu_period_us}")

            if limits.cpu_weight != 100:
                cpu_weight = cgroup_path / 'cpu.weight'
                if cpu_weight.exists():
                    cpu_weight.write_text(str(limits.cpu_weight))

            # Memory limits
            if limits.memory_max_bytes is not None:
                mem_max = cgroup_path / 'memory.max'
                if mem_max.exists():
                    mem_max.write_text(str(limits.memory_max_bytes))

            if limits.memory_high_bytes is not None:
                mem_high = cgroup_path / 'memory.high'
                if mem_high.exists():
                    mem_high.write_text(str(limits.memory_high_bytes))

            if limits.memory_swap_max_bytes is not None:
                swap_max = cgroup_path / 'memory.swap.max'
                if swap_max.exists():
                    swap_max.write_text(str(limits.memory_swap_max_bytes))

            # OOM control
            oom_group = cgroup_path / 'memory.oom.group'
            if oom_group.exists():
                oom_group.write_text('1' if limits.memory_oom_kill else '0')

            # I/O limits
            for io_limit in limits.io_max:
                io_max = cgroup_path / 'io.max'
                if io_max.exists():
                    io_max.write_text(io_limit)

            # PID limits
            if limits.pids_max is not None:
                pids_max = cgroup_path / 'pids.max'
                if pids_max.exists():
                    pids_max.write_text(str(limits.pids_max))

            # CPU affinity
            if limits.cpuset_cpus is not None:
                cpus = cgroup_path / 'cpuset.cpus'
                if cpus.exists():
                    cpus.write_text(limits.cpuset_cpus)

            if limits.cpuset_mems is not None:
                mems = cgroup_path / 'cpuset.mems'
                if mems.exists():
                    mems.write_text(limits.cpuset_mems)

            logger.debug(f"Set limits for cgroup: {cgroup_path}")

        except Exception as e:
            raise CgroupError(f"Failed to set limits: {e}")

    def add_process(self, cgroup_path: Path, pid: int) -> bool:
        """
        Add a process to a cgroup.

        Args:
            cgroup_path: Path to the cgroup
            pid: Process ID to add

        Returns:
            True if added successfully
        """
        try:
            procs_file = cgroup_path / 'cgroup.procs'
            procs_file.write_text(str(pid))
            logger.debug(f"Added PID {pid} to cgroup {cgroup_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to add process to cgroup: {e}")
            return False

    def get_processes(self, cgroup_path: Path) -> List[int]:
        """
        Get all processes in a cgroup.

        Args:
            cgroup_path: Path to the cgroup

        Returns:
            List of PIDs
        """
        try:
            procs_file = cgroup_path / 'cgroup.procs'
            if procs_file.exists():
                content = procs_file.read_text().strip()
                if content:
                    return [int(pid) for pid in content.split('\n')]
        except Exception:
            pass
        return []

    def _kill_processes(self, cgroup_path: Path, sig: int = signal.SIGKILL) -> None:
        """Kill all processes in a cgroup."""
        # Try cgroup.kill if available (Linux 5.14+)
        kill_file = cgroup_path / 'cgroup.kill'
        if kill_file.exists():
            try:
                kill_file.write_text('1')
                return
            except Exception:
                pass

        # Fallback: kill each process
        for pid in self.get_processes(cgroup_path):
            try:
                os.kill(pid, sig)
            except ProcessLookupError:
                pass

    def get_usage(self, cgroup_path: Path) -> ResourceUsage:
        """
        Get current resource usage for a cgroup.

        Args:
            cgroup_path: Path to the cgroup

        Returns:
            ResourceUsage with current stats
        """
        usage = ResourceUsage()

        try:
            # CPU usage
            cpu_stat = cgroup_path / 'cpu.stat'
            if cpu_stat.exists():
                for line in cpu_stat.read_text().strip().split('\n'):
                    key, value = line.split()
                    if key == 'usage_usec':
                        usage.cpu_usage_us = int(value)
                    elif key == 'user_usec':
                        usage.cpu_user_us = int(value)
                    elif key == 'system_usec':
                        usage.cpu_system_us = int(value)

            # Memory usage
            mem_current = cgroup_path / 'memory.current'
            if mem_current.exists():
                usage.memory_current_bytes = int(mem_current.read_text().strip())

            mem_peak = cgroup_path / 'memory.peak'
            if mem_peak.exists():
                usage.memory_peak_bytes = int(mem_peak.read_text().strip())

            swap_current = cgroup_path / 'memory.swap.current'
            if swap_current.exists():
                usage.memory_swap_bytes = int(swap_current.read_text().strip())

            # Memory events (OOM)
            mem_events = cgroup_path / 'memory.events'
            if mem_events.exists():
                for line in mem_events.read_text().strip().split('\n'):
                    key, value = line.split()
                    if key == 'oom_kill':
                        usage.oom_kills = int(value)

            # I/O usage
            io_stat = cgroup_path / 'io.stat'
            if io_stat.exists():
                for line in io_stat.read_text().strip().split('\n'):
                    if not line:
                        continue
                    parts = line.split()
                    for part in parts[1:]:
                        key, value = part.split('=')
                        if key == 'rbytes':
                            usage.io_read_bytes += int(value)
                        elif key == 'wbytes':
                            usage.io_write_bytes += int(value)

            # PID usage
            pids_current = cgroup_path / 'pids.current'
            if pids_current.exists():
                usage.pids_current = int(pids_current.read_text().strip())

            pids_peak = cgroup_path / 'pids.peak'
            if pids_peak.exists():
                usage.pids_peak = int(pids_peak.read_text().strip())

        except Exception as e:
            logger.debug(f"Error reading cgroup stats: {e}")

        return usage

    def freeze(self, cgroup_path: Path) -> bool:
        """
        Freeze all processes in a cgroup.

        Args:
            cgroup_path: Path to the cgroup

        Returns:
            True if frozen successfully
        """
        try:
            freeze_file = cgroup_path / 'cgroup.freeze'
            if freeze_file.exists():
                freeze_file.write_text('1')
                logger.debug(f"Frozen cgroup: {cgroup_path}")
                return True
        except Exception as e:
            logger.error(f"Failed to freeze cgroup: {e}")
        return False

    def thaw(self, cgroup_path: Path) -> bool:
        """
        Thaw (unfreeze) all processes in a cgroup.

        Args:
            cgroup_path: Path to the cgroup

        Returns:
            True if thawed successfully
        """
        try:
            freeze_file = cgroup_path / 'cgroup.freeze'
            if freeze_file.exists():
                freeze_file.write_text('0')
                logger.debug(f"Thawed cgroup: {cgroup_path}")
                return True
        except Exception as e:
            logger.error(f"Failed to thaw cgroup: {e}")
        return False

    def cleanup(self) -> None:
        """Clean up all cgroups created by this manager."""
        for cgroup_path in list(self._created_cgroups):
            self.delete_cgroup(cgroup_path)


if __name__ == '__main__':
    print("Testing Cgroup Manager...")

    manager = CgroupManager()

    print(f"\nCapabilities: {manager.get_capabilities()}")
    print(f"Can manage cgroups: {manager.can_manage_cgroups()}")

    if manager.can_manage_cgroups():
        print("\nCreating test cgroup...")
        try:
            cgroup = manager.create_cgroup("test-sandbox")
            print(f"Created: {cgroup}")

            # Set limits
            limits = CgroupLimits.standard()
            print(f"\nSetting limits:")
            print(f"  CPU: {limits.cpu_max_cores} cores")
            print(f"  Memory: {limits.memory_max_bytes / 1024 / 1024:.0f} MB")
            print(f"  PIDs: {limits.pids_max}")

            manager.set_limits(cgroup, limits)

            # Check usage
            usage = manager.get_usage(cgroup)
            print(f"\nCurrent usage:")
            print(f"  Memory: {usage.memory_current_bytes / 1024:.1f} KB")
            print(f"  PIDs: {usage.pids_current}")

            # Cleanup
            print("\nCleaning up...")
            manager.delete_cgroup(cgroup)
            print("Done!")

        except CgroupError as e:
            print(f"Cgroup error: {e}")
    else:
        print("\nCgroup management not available")
        print("(Requires cgroups v2 and appropriate permissions)")

    print("\nCgroup manager test complete.")
