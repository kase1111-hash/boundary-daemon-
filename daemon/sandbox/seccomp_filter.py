"""
Seccomp-BPF Syscall Filtering for Boundary Daemon Sandbox

Provides syscall filtering using Linux seccomp-bpf:
- Define allow/deny/trace rules per syscall
- Pre-built profiles for different restriction levels
- Integration with boundary modes

Seccomp (SECure COMPuting) restricts which syscalls a process can make.
When a blocked syscall is attempted, the process is killed or receives EPERM.

This module provides both:
1. Direct seccomp via libseccomp (if available)
2. Fallback via subprocess with seccomp-tools

Note: Seccomp is one-way - once enabled, it cannot be disabled.
"""

import ctypes
import ctypes.util
import logging
import os
import struct
from dataclasses import dataclass, field
from enum import IntEnum, auto
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# Seccomp constants from linux/seccomp.h
SECCOMP_MODE_STRICT = 1
SECCOMP_MODE_FILTER = 2

SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_KILL_THREAD = 0x00000000
SECCOMP_RET_TRAP = 0x00030000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_TRACE = 0x7ff00000
SECCOMP_RET_LOG = 0x7ffc0000
SECCOMP_RET_ALLOW = 0x7fff0000

# prctl constants
PR_SET_SECCOMP = 22
PR_SET_NO_NEW_PRIVS = 38

# BPF constants
BPF_LD = 0x00
BPF_W = 0x00
BPF_ABS = 0x20
BPF_JMP = 0x05
BPF_JEQ = 0x10
BPF_K = 0x00
BPF_RET = 0x06

# Architecture constants for seccomp
AUDIT_ARCH_X86_64 = 0xc000003e
AUDIT_ARCH_I386 = 0x40000003
AUDIT_ARCH_AARCH64 = 0xc00000b7


class SeccompAction(IntEnum):
    """Actions to take when a syscall matches."""
    ALLOW = auto()      # Allow the syscall
    DENY = auto()       # Block with EPERM
    KILL = auto()       # Kill the process
    TRAP = auto()       # Send SIGSYS
    LOG = auto()        # Log and allow
    TRACE = auto()      # Enable ptrace


@dataclass
class SyscallRule:
    """A rule for a specific syscall."""
    syscall_nr: int
    syscall_name: str
    action: SeccompAction
    args: Optional[List[Tuple[int, int, int]]] = None  # (arg_index, value, mask) for arg filtering


@dataclass
class SeccompProfile:
    """A complete seccomp profile with default action and rules."""
    name: str
    description: str = ""
    default_action: SeccompAction = SeccompAction.DENY

    # Explicit rules (override default)
    rules: List[SyscallRule] = field(default_factory=list)

    # Convenience sets
    allowed_syscalls: Set[str] = field(default_factory=set)
    denied_syscalls: Set[str] = field(default_factory=set)


# Common syscall numbers for x86_64 Linux
# These are the most commonly needed syscalls
SYSCALL_NUMBERS_X86_64 = {
    # Process
    'exit': 60,
    'exit_group': 231,
    'fork': 57,
    'vfork': 58,
    'clone': 56,
    'clone3': 435,
    'execve': 59,
    'execveat': 322,
    'wait4': 61,
    'waitid': 247,
    'kill': 62,
    'getpid': 39,
    'getppid': 110,
    'gettid': 186,
    'prctl': 157,
    'arch_prctl': 158,

    # Memory
    'brk': 12,
    'mmap': 9,
    'munmap': 11,
    'mprotect': 10,
    'mremap': 25,
    'msync': 26,
    'madvise': 28,
    'mlock': 149,
    'munlock': 150,

    # File descriptors
    'read': 0,
    'write': 1,
    'open': 2,
    'openat': 257,
    'close': 3,
    'lseek': 8,
    'pread64': 17,
    'pwrite64': 18,
    'readv': 19,
    'writev': 20,
    'dup': 32,
    'dup2': 33,
    'dup3': 292,
    'pipe': 22,
    'pipe2': 293,

    # File operations
    'stat': 4,
    'fstat': 5,
    'lstat': 6,
    'newfstatat': 262,
    'access': 21,
    'faccessat': 269,
    'faccessat2': 439,
    'unlink': 87,
    'unlinkat': 263,
    'rename': 82,
    'renameat': 264,
    'renameat2': 316,
    'mkdir': 83,
    'mkdirat': 258,
    'rmdir': 84,
    'link': 86,
    'linkat': 265,
    'symlink': 88,
    'symlinkat': 266,
    'readlink': 89,
    'readlinkat': 267,
    'chmod': 90,
    'fchmod': 91,
    'fchmodat': 268,
    'chown': 92,
    'fchown': 93,
    'fchownat': 260,
    'truncate': 76,
    'ftruncate': 77,
    'getcwd': 79,
    'chdir': 80,
    'fchdir': 81,

    # Directory
    'getdents': 78,
    'getdents64': 217,

    # Poll/Select
    'poll': 7,
    'ppoll': 271,
    'select': 23,
    'pselect6': 270,
    'epoll_create': 213,
    'epoll_create1': 291,
    'epoll_ctl': 233,
    'epoll_wait': 232,
    'epoll_pwait': 281,
    'epoll_pwait2': 441,

    # Network
    'socket': 41,
    'connect': 42,
    'accept': 43,
    'accept4': 288,
    'bind': 49,
    'listen': 50,
    'sendto': 44,
    'recvfrom': 45,
    'sendmsg': 46,
    'recvmsg': 47,
    'shutdown': 48,
    'getsockname': 51,
    'getpeername': 52,
    'socketpair': 53,
    'setsockopt': 54,
    'getsockopt': 55,

    # Time
    'time': 201,
    'gettimeofday': 96,
    'clock_gettime': 228,
    'clock_getres': 229,
    'clock_nanosleep': 230,
    'nanosleep': 35,

    # Signals
    'rt_sigaction': 13,
    'rt_sigprocmask': 14,
    'rt_sigreturn': 15,
    'rt_sigsuspend': 130,
    'sigaltstack': 131,

    # User/Group
    'getuid': 102,
    'getgid': 104,
    'geteuid': 107,
    'getegid': 108,
    'setuid': 105,
    'setgid': 106,
    'setreuid': 113,
    'setregid': 114,
    'getgroups': 115,
    'setgroups': 116,
    'setresuid': 117,
    'setresgid': 119,

    # I/O control
    'ioctl': 16,
    'fcntl': 72,

    # IPC
    'shmget': 29,
    'shmat': 30,
    'shmctl': 31,
    'semget': 64,
    'semop': 65,
    'semctl': 66,
    'msgget': 68,
    'msgsnd': 69,
    'msgrcv': 70,
    'msgctl': 71,

    # Misc
    'uname': 63,
    'getrandom': 318,
    'futex': 202,
    'set_tid_address': 218,
    'set_robust_list': 273,
    'get_robust_list': 274,
    'sched_yield': 24,
    'sched_getaffinity': 204,
    'sched_setaffinity': 203,
    'capget': 125,
    'capset': 126,

    # Dangerous syscalls
    'ptrace': 101,
    'mount': 165,
    'umount2': 166,
    'pivot_root': 155,
    'chroot': 161,
    'reboot': 169,
    'swapon': 167,
    'swapoff': 168,
    'kexec_load': 246,
    'init_module': 175,
    'finit_module': 313,
    'delete_module': 176,
    'perf_event_open': 298,
    'bpf': 321,
    'userfaultfd': 323,
    'memfd_create': 319,
    'io_uring_setup': 425,
    'io_uring_enter': 426,
    'io_uring_register': 427,
}


class SeccompFilter:
    """
    Manages seccomp-bpf filters.

    Usage:
        filter = SeccompFilter()

        # Load a predefined profile
        filter.load_profile(SeccompProfile.STANDARD)

        # Or build custom rules
        filter.set_default_action(SeccompAction.DENY)
        filter.allow_syscall('read')
        filter.allow_syscall('write')
        filter.deny_syscall('ptrace')

        # Apply to current process (irreversible!)
        filter.apply()
    """

    def __init__(self):
        self._libc = self._load_libc()
        self._rules: Dict[int, SeccompAction] = {}
        self._default_action = SeccompAction.DENY
        self._applied = False
        self._arch = self._detect_arch()
        self._syscall_numbers = SYSCALL_NUMBERS_X86_64

    def _load_libc(self) -> Optional[ctypes.CDLL]:
        """Load libc for prctl."""
        try:
            libc_name = ctypes.util.find_library('c')
            if libc_name:
                return ctypes.CDLL(libc_name, use_errno=True)
        except Exception as e:
            logger.warning(f"Could not load libc: {e}")
        return None

    def _detect_arch(self) -> int:
        """Detect system architecture."""
        import platform
        machine = platform.machine()

        if machine == 'x86_64':
            return AUDIT_ARCH_X86_64
        elif machine in ('i386', 'i686'):
            return AUDIT_ARCH_I386
        elif machine == 'aarch64':
            return AUDIT_ARCH_AARCH64
        else:
            logger.warning(f"Unknown architecture: {machine}, defaulting to x86_64")
            return AUDIT_ARCH_X86_64

    def set_default_action(self, action: SeccompAction) -> None:
        """Set the default action for unmatched syscalls."""
        if self._applied:
            raise RuntimeError("Cannot modify filter after it's applied")
        self._default_action = action

    def _get_syscall_nr(self, name: str) -> Optional[int]:
        """Get syscall number by name."""
        return self._syscall_numbers.get(name)

    def allow_syscall(self, name: str) -> bool:
        """Allow a syscall by name."""
        if self._applied:
            raise RuntimeError("Cannot modify filter after it's applied")

        nr = self._get_syscall_nr(name)
        if nr is None:
            logger.warning(f"Unknown syscall: {name}")
            return False

        self._rules[nr] = SeccompAction.ALLOW
        return True

    def deny_syscall(self, name: str) -> bool:
        """Deny a syscall by name (returns EPERM)."""
        if self._applied:
            raise RuntimeError("Cannot modify filter after it's applied")

        nr = self._get_syscall_nr(name)
        if nr is None:
            logger.warning(f"Unknown syscall: {name}")
            return False

        self._rules[nr] = SeccompAction.DENY
        return True

    def kill_on_syscall(self, name: str) -> bool:
        """Kill process if syscall is attempted."""
        if self._applied:
            raise RuntimeError("Cannot modify filter after it's applied")

        nr = self._get_syscall_nr(name)
        if nr is None:
            logger.warning(f"Unknown syscall: {name}")
            return False

        self._rules[nr] = SeccompAction.KILL
        return True

    def load_profile(self, profile: SeccompProfile) -> None:
        """Load a complete seccomp profile."""
        if self._applied:
            raise RuntimeError("Cannot modify filter after it's applied")

        self._default_action = profile.default_action
        self._rules.clear()

        # Apply explicit rules
        for rule in profile.rules:
            self._rules[rule.syscall_nr] = rule.action

        # Apply allowed set
        for name in profile.allowed_syscalls:
            nr = self._get_syscall_nr(name)
            if nr is not None:
                self._rules[nr] = SeccompAction.ALLOW

        # Apply denied set
        for name in profile.denied_syscalls:
            nr = self._get_syscall_nr(name)
            if nr is not None:
                self._rules[nr] = SeccompAction.DENY

    def _build_bpf_program(self) -> bytes:
        """Build a BPF program from current rules."""
        # BPF filter structure:
        # 1. Load architecture and verify
        # 2. Load syscall number
        # 3. For each rule, add jump to action
        # 4. Default action

        instructions = []

        def bpf_stmt(code: int, k: int) -> bytes:
            """Build a BPF_STMT."""
            return struct.pack('HBBI', code, 0, 0, k)

        def bpf_jump(code: int, k: int, jt: int, jf: int) -> bytes:
            """Build a BPF_JUMP."""
            return struct.pack('HBBI', code, jt, jf, k)

        # Load architecture (offset 4 in seccomp_data)
        instructions.append(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 4))

        # Verify architecture (jump to kill if wrong)
        arch_check = bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, self._arch, 1, 0)
        instructions.append(arch_check)

        # Kill if wrong arch
        instructions.append(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS))

        # Load syscall number (offset 0 in seccomp_data)
        instructions.append(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 0))

        # Add rules for each syscall
        sorted_rules = sorted(self._rules.items())

        for syscall_nr, action in sorted_rules:
            # Calculate jump target (how many instructions to skip)
            # Each rule adds 2 instructions: compare + action

            if action == SeccompAction.ALLOW:
                ret_val = SECCOMP_RET_ALLOW
            elif action == SeccompAction.DENY:
                ret_val = SECCOMP_RET_ERRNO | 1  # EPERM
            elif action == SeccompAction.KILL:
                ret_val = SECCOMP_RET_KILL_PROCESS
            elif action == SeccompAction.TRAP:
                ret_val = SECCOMP_RET_TRAP
            elif action == SeccompAction.LOG:
                ret_val = SECCOMP_RET_LOG
            else:
                ret_val = SECCOMP_RET_ERRNO | 1

            # Jump to return if match, else continue
            instructions.append(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, syscall_nr, 0, 1))
            instructions.append(bpf_stmt(BPF_RET | BPF_K, ret_val))

        # Default action
        if self._default_action == SeccompAction.ALLOW:
            default_ret = SECCOMP_RET_ALLOW
        elif self._default_action == SeccompAction.KILL:
            default_ret = SECCOMP_RET_KILL_PROCESS
        else:
            default_ret = SECCOMP_RET_ERRNO | 1  # EPERM

        instructions.append(bpf_stmt(BPF_RET | BPF_K, default_ret))

        return b''.join(instructions)

    def apply(self) -> bool:
        """
        Apply the seccomp filter to the current process.

        WARNING: This is IRREVERSIBLE. Once applied, the filter
        cannot be removed or loosened.

        Returns:
            True if applied successfully
        """
        if self._applied:
            logger.warning("Seccomp filter already applied")
            return True

        if not self._libc:
            logger.error("libc not available for seccomp")
            return False

        try:
            # First, set NO_NEW_PRIVS (required for non-root)
            result = self._libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
            if result != 0:
                logger.error("Failed to set NO_NEW_PRIVS")
                return False

            # Build BPF program
            bpf_program = self._build_bpf_program()
            instruction_count = len(bpf_program) // 8  # Each instruction is 8 bytes

            # Create sock_fprog structure
            # struct sock_fprog { unsigned short len; struct sock_filter *filter; }
            class SockFprog(ctypes.Structure):
                _fields_ = [
                    ('len', ctypes.c_ushort),
                    ('filter', ctypes.c_void_p),
                ]

            program = SockFprog()
            program.len = instruction_count

            # Create buffer for BPF instructions
            buf = ctypes.create_string_buffer(bpf_program)
            program.filter = ctypes.addressof(buf)

            # Apply filter via prctl
            result = self._libc.prctl(
                PR_SET_SECCOMP,
                SECCOMP_MODE_FILTER,
                ctypes.byref(program),
                0,
                0,
            )

            if result != 0:
                errno = ctypes.get_errno()
                logger.error(f"Failed to apply seccomp filter: errno {errno}")
                return False

            self._applied = True
            logger.info(f"Seccomp filter applied with {instruction_count} instructions")
            return True

        except Exception as e:
            logger.error(f"Error applying seccomp filter: {e}")
            return False

    def get_stats(self) -> Dict:
        """Get filter statistics."""
        allowed = sum(1 for a in self._rules.values() if a == SeccompAction.ALLOW)
        denied = sum(1 for a in self._rules.values() if a == SeccompAction.DENY)
        killed = sum(1 for a in self._rules.values() if a == SeccompAction.KILL)

        return {
            'total_rules': len(self._rules),
            'allowed': allowed,
            'denied': denied,
            'killed': killed,
            'default_action': self._default_action.name,
            'applied': self._applied,
            'architecture': hex(self._arch),
        }


# Predefined profiles for different restriction levels
class SeccompProfiles:
    """Predefined seccomp profiles."""

    @staticmethod
    def minimal() -> SeccompProfile:
        """
        Minimal profile - only essential syscalls.
        Suitable for simple programs that don't need network or IPC.
        """
        return SeccompProfile(
            name="minimal",
            description="Only essential syscalls for basic execution",
            default_action=SeccompAction.DENY,
            allowed_syscalls={
                # Essential
                'exit', 'exit_group', 'read', 'write', 'close',
                # Memory
                'brk', 'mmap', 'munmap', 'mprotect',
                # Signals
                'rt_sigaction', 'rt_sigprocmask', 'rt_sigreturn',
                # Info
                'getpid', 'gettid', 'uname', 'getcwd',
                # Time
                'clock_gettime', 'gettimeofday',
                # Fd basics
                'fstat', 'newfstatat', 'lseek', 'dup', 'dup2',
                # Required for many programs
                'arch_prctl', 'set_tid_address', 'set_robust_list',
                'futex', 'getrandom',
            },
        )

    @staticmethod
    def standard() -> SeccompProfile:
        """
        Standard profile - common syscalls for typical applications.
        No network, limited IPC, filesystem access allowed.
        """
        return SeccompProfile(
            name="standard",
            description="Standard syscalls for typical applications",
            default_action=SeccompAction.DENY,
            allowed_syscalls={
                # From minimal
                'exit', 'exit_group', 'read', 'write', 'close',
                'brk', 'mmap', 'munmap', 'mprotect', 'mremap', 'madvise',
                'rt_sigaction', 'rt_sigprocmask', 'rt_sigreturn',
                'getpid', 'gettid', 'getppid', 'uname', 'getcwd',
                'clock_gettime', 'clock_getres', 'gettimeofday', 'nanosleep',
                'fstat', 'newfstatat', 'lseek', 'dup', 'dup2', 'dup3',
                'arch_prctl', 'set_tid_address', 'set_robust_list',
                'futex', 'getrandom',

                # Filesystem
                'open', 'openat', 'stat', 'lstat', 'access', 'faccessat',
                'readlink', 'readlinkat', 'getdents', 'getdents64',
                'chdir', 'fchdir', 'fcntl', 'ioctl',
                'pread64', 'pwrite64', 'readv', 'writev',
                'pipe', 'pipe2',

                # Polling
                'poll', 'ppoll', 'select', 'pselect6',
                'epoll_create', 'epoll_create1', 'epoll_ctl',
                'epoll_wait', 'epoll_pwait',

                # User info
                'getuid', 'getgid', 'geteuid', 'getegid', 'getgroups',

                # Scheduling
                'sched_yield', 'sched_getaffinity',

                # Misc
                'prctl', 'capget',
            },
            denied_syscalls={
                # Dangerous - explicit deny
                'ptrace', 'mount', 'umount2', 'pivot_root', 'chroot',
                'reboot', 'kexec_load', 'init_module', 'finit_module',
                'delete_module', 'perf_event_open', 'bpf',
            },
        )

    @staticmethod
    def network() -> SeccompProfile:
        """
        Network profile - standard + network syscalls.
        """
        profile = SeccompProfiles.standard()
        profile.name = "network"
        profile.description = "Standard syscalls plus networking"

        profile.allowed_syscalls.update({
            'socket', 'connect', 'accept', 'accept4',
            'bind', 'listen', 'sendto', 'recvfrom',
            'sendmsg', 'recvmsg', 'shutdown',
            'getsockname', 'getpeername', 'socketpair',
            'setsockopt', 'getsockopt',
        })

        return profile

    @staticmethod
    def untrusted() -> SeccompProfile:
        """
        Untrusted profile - very restrictive for untrusted code.
        No filesystem writes, no network, no process creation.
        """
        return SeccompProfile(
            name="untrusted",
            description="Very restrictive for untrusted code",
            default_action=SeccompAction.KILL,  # Kill on violation
            allowed_syscalls={
                # Absolute minimum
                'exit', 'exit_group',
                'read', 'write',  # Only to already-open fds
                'close', 'fstat', 'lseek',
                'brk', 'mmap', 'munmap', 'mprotect',
                'rt_sigaction', 'rt_sigprocmask', 'rt_sigreturn',
                'getpid', 'gettid',
                'clock_gettime',
                'arch_prctl', 'set_tid_address',
                'futex', 'getrandom',
            },
        )

    @staticmethod
    def for_boundary_mode(mode: int) -> SeccompProfile:
        """
        Get appropriate profile for a boundary mode.

        Args:
            mode: Boundary mode (0=OPEN to 5=LOCKDOWN)

        Returns:
            Appropriate SeccompProfile
        """
        if mode >= 5:  # LOCKDOWN
            # No new processes allowed - return ultra-restrictive
            return SeccompProfile(
                name="lockdown",
                description="No syscalls allowed (lockdown mode)",
                default_action=SeccompAction.KILL,
                allowed_syscalls={'exit', 'exit_group'},
            )
        elif mode >= 4:  # COLDROOM
            return SeccompProfiles.untrusted()
        elif mode >= 3:  # AIRGAP
            return SeccompProfiles.minimal()
        elif mode >= 2:  # TRUSTED
            return SeccompProfiles.standard()
        elif mode >= 1:  # RESTRICTED
            return SeccompProfiles.standard()
        else:  # OPEN
            return SeccompProfiles.network()


if __name__ == '__main__':
    print("Testing Seccomp Filter...")

    filter = SeccompFilter()

    # Test profile loading
    profile = SeccompProfiles.standard()
    print(f"\nLoaded profile: {profile.name}")
    print(f"Description: {profile.description}")
    print(f"Default action: {profile.default_action.name}")
    print(f"Allowed syscalls: {len(profile.allowed_syscalls)}")

    filter.load_profile(profile)
    stats = filter.get_stats()
    print(f"\nFilter stats: {stats}")

    # Test BPF program building (without applying)
    print("\nBuilding BPF program...")
    bpf = filter._build_bpf_program()
    print(f"BPF program size: {len(bpf)} bytes ({len(bpf)//8} instructions)")

    # Test boundary mode profiles
    print("\nBoundary mode profiles:")
    for mode in range(6):
        mode_profile = SeccompProfiles.for_boundary_mode(mode)
        print(f"  Mode {mode}: {mode_profile.name} ({len(mode_profile.allowed_syscalls)} allowed)")

    print("\nNote: Not applying filter in test mode to avoid breaking the process")
    print("\nSeccomp filter test complete.")
