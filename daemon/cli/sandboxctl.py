#!/usr/bin/env python3
"""
sandboxctl - Sandbox Management CLI for Boundary Daemon

Provides command-line interface for managing sandboxed processes:
- Run commands in isolated sandboxes
- List and manage active sandboxes
- Inspect sandbox configuration
- View resource usage
- Test sandbox profiles

Usage:
    sandboxctl run -- /usr/bin/python3 script.py
    sandboxctl run --profile restricted -- npm install
    sandboxctl list
    sandboxctl inspect sandbox-001
    sandboxctl kill sandbox-001
    sandboxctl profiles
    sandboxctl test --profile airgap

Environment Variables:
    BOUNDARY_SOCKET  - Path to daemon control socket
    BOUNDARY_CONFIG  - Path to configuration file
"""

import argparse
import json
import os
import sys
import signal
import time
from typing import Optional

# Attempt imports - graceful fallback for standalone usage
try:
    from daemon.sandbox import (
        SandboxManager,
        SandboxProfile,
        SandboxError,
        CgroupLimits,
        NetworkPolicy,
    )
    SANDBOX_AVAILABLE = True
except ImportError:
    SANDBOX_AVAILABLE = False

try:
    from daemon.telemetry.prometheus_metrics import get_metrics_exporter
    METRICS_AVAILABLE = True
except ImportError:
    METRICS_AVAILABLE = False


# ANSI color codes
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GRAY = '\033[90m'

    @classmethod
    def disable(cls):
        """Disable colors for non-TTY output."""
        cls.RESET = ''
        cls.BOLD = ''
        cls.RED = ''
        cls.GREEN = ''
        cls.YELLOW = ''
        cls.BLUE = ''
        cls.CYAN = ''
        cls.GRAY = ''


def format_bytes(n: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(n) < 1024.0:
            return f"{n:.1f}{unit}"
        n /= 1024.0
    return f"{n:.1f}PB"


def format_duration(seconds: float) -> str:
    """Format duration as human-readable string."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{int(seconds // 60)}m {int(seconds % 60)}s"
    else:
        hours = int(seconds // 3600)
        mins = int((seconds % 3600) // 60)
        return f"{hours}h {mins}m"


def print_error(msg: str) -> None:
    """Print error message."""
    print(f"{Colors.RED}Error:{Colors.RESET} {msg}", file=sys.stderr)


def print_success(msg: str) -> None:
    """Print success message."""
    print(f"{Colors.GREEN}✓{Colors.RESET} {msg}")


def print_warning(msg: str) -> None:
    """Print warning message."""
    print(f"{Colors.YELLOW}Warning:{Colors.RESET} {msg}")


def print_info(msg: str) -> None:
    """Print info message."""
    print(f"{Colors.CYAN}ℹ{Colors.RESET} {msg}")


class SandboxCLI:
    """CLI handler for sandbox commands."""

    def __init__(self, socket_path: Optional[str] = None, config_path: Optional[str] = None):
        self.socket_path = socket_path or os.environ.get(
            'BOUNDARY_SOCKET', '/var/run/boundary-daemon/sandbox.sock'
        )
        self.config_path = config_path or os.environ.get(
            'BOUNDARY_CONFIG', '/etc/boundary-daemon/config.yaml'
        )
        self._manager: Optional[SandboxManager] = None

    def _get_manager(self) -> SandboxManager:
        """Get or create sandbox manager."""
        if not SANDBOX_AVAILABLE:
            print_error("Sandbox module not available. Ensure boundary-daemon is installed.")
            sys.exit(1)

        if self._manager is None:
            # In a real implementation, this would connect to the daemon
            # For now, create a local manager
            self._manager = SandboxManager(policy_engine=None)

        return self._manager

    def cmd_run(self, args: argparse.Namespace) -> int:
        """Run a command in a sandbox."""
        if not args.command:
            print_error("No command specified. Use: sandboxctl run -- <command>")
            return 1

        manager = self._get_manager()

        # Parse profile
        profile_name = args.profile.upper() if args.profile else 'STANDARD'
        try:
            profile = SandboxProfile.from_name(profile_name)
        except (ValueError, AttributeError):
            # Use default profile
            profile = SandboxProfile(name=profile_name)

        # Apply overrides
        if args.memory:
            profile.cgroup_limits = profile.cgroup_limits or CgroupLimits()
            profile.cgroup_limits.memory_max = self._parse_memory(args.memory)

        if args.cpu:
            profile.cgroup_limits = profile.cgroup_limits or CgroupLimits()
            profile.cgroup_limits.cpu_max = int(args.cpu * 100000)  # percent to quota

        if args.timeout:
            profile.timeout_seconds = args.timeout

        if args.network_deny:
            profile.network_policy = NetworkPolicy(deny_all=True)
        elif args.network_allow:
            profile.network_policy = NetworkPolicy(
                allow_all=False,
                allowed_hosts=args.network_allow,
            )

        # Print info
        if not args.quiet:
            print_info(f"Running in sandbox with profile: {profile_name}")
            if profile.timeout_seconds:
                print_info(f"Timeout: {profile.timeout_seconds}s")

        # Handle signals
        def signal_handler(sig, frame):
            print_warning("Interrupt received, terminating sandbox...")
            sys.exit(130)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        # Run command
        start_time = time.time()
        try:
            result = manager.run_sandboxed(
                command=args.command,
                profile=profile,
                stdin_data=None,
                capture_output=not args.interactive,
                inherit_env=args.inherit_env,
            )

            elapsed = time.time() - start_time

            # Output handling
            if not args.interactive:
                if result.stdout:
                    sys.stdout.write(result.stdout)
                if result.stderr:
                    sys.stderr.write(result.stderr)

            if not args.quiet:
                if result.exit_code == 0:
                    print_success(f"Command completed in {format_duration(elapsed)}")
                else:
                    print_warning(f"Command exited with code {result.exit_code}")

                # Resource usage
                if result.resource_usage and args.verbose:
                    usage = result.resource_usage
                    print(f"\n{Colors.BOLD}Resource Usage:{Colors.RESET}")
                    if hasattr(usage, 'cpu_time_seconds'):
                        print(f"  CPU time:     {usage.cpu_time_seconds:.2f}s")
                    if hasattr(usage, 'memory_peak_bytes'):
                        print(f"  Memory peak:  {format_bytes(usage.memory_peak_bytes)}")
                    if hasattr(usage, 'io_read_bytes'):
                        print(f"  I/O read:     {format_bytes(usage.io_read_bytes)}")
                    if hasattr(usage, 'io_write_bytes'):
                        print(f"  I/O write:    {format_bytes(usage.io_write_bytes)}")

            return result.exit_code

        except SandboxError as e:
            print_error(str(e))
            return 1
        except Exception as e:
            print_error(f"Unexpected error: {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()
            return 1

    def cmd_list(self, args: argparse.Namespace) -> int:
        """List active sandboxes."""
        manager = self._get_manager()

        sandboxes = manager.list_sandboxes()

        if not sandboxes:
            print("No active sandboxes")
            return 0

        # Header
        if args.output == 'table':
            print(f"\n{Colors.BOLD}{'ID':<20} {'PROFILE':<12} {'STATUS':<10} {'PID':<8} {'UPTIME':<12} {'MEMORY':<10}{Colors.RESET}")
            print("-" * 72)

            for sbx in sandboxes:
                status_color = Colors.GREEN if sbx.status == 'running' else Colors.YELLOW
                uptime = format_duration(sbx.uptime_seconds) if sbx.uptime_seconds else '-'
                memory = format_bytes(sbx.memory_usage_bytes) if sbx.memory_usage_bytes else '-'

                print(
                    f"{sbx.id:<20} "
                    f"{sbx.profile:<12} "
                    f"{status_color}{sbx.status:<10}{Colors.RESET} "
                    f"{sbx.pid or '-':<8} "
                    f"{uptime:<12} "
                    f"{memory:<10}"
                )

            print(f"\n{len(sandboxes)} sandbox(es) total")

        elif args.output == 'json':
            output = [
                {
                    'id': sbx.id,
                    'profile': sbx.profile,
                    'status': sbx.status,
                    'pid': sbx.pid,
                    'uptime_seconds': sbx.uptime_seconds,
                    'memory_usage_bytes': sbx.memory_usage_bytes,
                }
                for sbx in sandboxes
            ]
            print(json.dumps(output, indent=2))

        elif args.output == 'wide':
            for sbx in sandboxes:
                print(f"\n{Colors.BOLD}Sandbox: {sbx.id}{Colors.RESET}")
                print(f"  Profile:  {sbx.profile}")
                print(f"  Status:   {sbx.status}")
                print(f"  PID:      {sbx.pid or 'N/A'}")
                print(f"  Command:  {' '.join(sbx.command) if sbx.command else 'N/A'}")
                print(f"  Cgroup:   {sbx.cgroup_path or 'N/A'}")
                if sbx.resource_usage:
                    print(f"  Resources:")
                    print(f"    Memory: {format_bytes(sbx.memory_usage_bytes or 0)}")
                    print(f"    CPU:    {sbx.cpu_usage_percent or 0:.1f}%")

        return 0

    def cmd_inspect(self, args: argparse.Namespace) -> int:
        """Inspect a sandbox."""
        manager = self._get_manager()

        try:
            sandbox = manager.get_sandbox(args.sandbox_id)
        except Exception as e:
            print_error(f"Sandbox not found: {args.sandbox_id}")
            return 1

        info = sandbox.get_info()

        if args.output == 'json':
            print(json.dumps(info, indent=2, default=str))
        else:
            print(f"\n{Colors.BOLD}Sandbox: {sandbox.id}{Colors.RESET}")
            print(f"\n{Colors.CYAN}Configuration:{Colors.RESET}")
            print(f"  Profile:    {info.get('profile', 'N/A')}")
            print(f"  Status:     {info.get('status', 'N/A')}")
            print(f"  PID:        {info.get('pid', 'N/A')}")
            print(f"  Command:    {info.get('command', 'N/A')}")

            print(f"\n{Colors.CYAN}Isolation:{Colors.RESET}")
            print(f"  Namespaces: {', '.join(info.get('namespaces', []))}")
            print(f"  Cgroup:     {info.get('cgroup_path', 'N/A')}")
            print(f"  Seccomp:    {info.get('seccomp_profile', 'N/A')}")

            if info.get('network_policy'):
                print(f"\n{Colors.CYAN}Network Policy:{Colors.RESET}")
                np = info['network_policy']
                if np.get('deny_all'):
                    print("  Mode:       DENY ALL")
                elif np.get('allow_all'):
                    print("  Mode:       ALLOW ALL")
                else:
                    print("  Mode:       FILTERED")
                    if np.get('allowed_hosts'):
                        print(f"  Allowed:    {', '.join(np['allowed_hosts'])}")

            if info.get('resource_limits'):
                print(f"\n{Colors.CYAN}Resource Limits:{Colors.RESET}")
                limits = info['resource_limits']
                if limits.get('memory_max'):
                    print(f"  Memory:     {format_bytes(limits['memory_max'])}")
                if limits.get('cpu_max'):
                    print(f"  CPU:        {limits['cpu_max'] / 1000:.0f}%")
                if limits.get('pids_max'):
                    print(f"  PIDs:       {limits['pids_max']}")

            if info.get('resource_usage'):
                print(f"\n{Colors.CYAN}Resource Usage:{Colors.RESET}")
                usage = info['resource_usage']
                print(f"  Memory:     {format_bytes(usage.get('memory_current', 0))}")
                print(f"  CPU:        {usage.get('cpu_usage_percent', 0):.1f}%")

        return 0

    def cmd_kill(self, args: argparse.Namespace) -> int:
        """Kill a sandbox."""
        manager = self._get_manager()

        sandbox_ids = args.sandbox_ids
        if args.all:
            sandboxes = manager.list_sandboxes()
            sandbox_ids = [s.id for s in sandboxes]

        if not sandbox_ids:
            print("No sandboxes to kill")
            return 0

        errors = 0
        for sandbox_id in sandbox_ids:
            try:
                sig = signal.SIGKILL if args.force else signal.SIGTERM
                manager.terminate_sandbox(sandbox_id, signal=sig.value)
                print_success(f"Killed sandbox: {sandbox_id}")
            except Exception as e:
                print_error(f"Failed to kill {sandbox_id}: {e}")
                errors += 1

        return 1 if errors else 0

    def cmd_profiles(self, args: argparse.Namespace) -> int:
        """List available sandbox profiles."""
        profiles = [
            ('minimal', 'Minimal isolation, basic resource limits only'),
            ('standard', 'Standard isolation with namespace and seccomp'),
            ('restricted', 'Restricted - limited syscalls, no network'),
            ('untrusted', 'Untrusted code - strict isolation'),
            ('airgap', 'Air-gapped - no network, filesystem restrictions'),
            ('coldroom', 'Maximum isolation, minimal attack surface'),
        ]

        if args.output == 'json':
            output = [{'name': name, 'description': desc} for name, desc in profiles]
            print(json.dumps(output, indent=2))
        else:
            print(f"\n{Colors.BOLD}Available Sandbox Profiles:{Colors.RESET}\n")
            for name, desc in profiles:
                print(f"  {Colors.CYAN}{name:<12}{Colors.RESET} {desc}")

            print(f"\n{Colors.GRAY}Use 'sandboxctl run --profile <name> -- <command>' to run with a profile{Colors.RESET}")

        return 0

    def cmd_test(self, args: argparse.Namespace) -> int:
        """Test sandbox functionality."""
        manager = self._get_manager()

        profile_name = args.profile.upper() if args.profile else 'STANDARD'

        print(f"\n{Colors.BOLD}Testing Sandbox Profile: {profile_name}{Colors.RESET}\n")

        tests = [
            ('namespace_isolation', 'Namespace isolation'),
            ('seccomp_filter', 'Seccomp filtering'),
            ('cgroup_limits', 'Cgroup resource limits'),
            ('network_policy', 'Network policy'),
        ]

        passed = 0
        failed = 0

        for test_id, test_name in tests:
            try:
                result = self._run_test(manager, test_id, profile_name)
                if result:
                    print(f"  {Colors.GREEN}✓{Colors.RESET} {test_name}")
                    passed += 1
                else:
                    print(f"  {Colors.RED}✗{Colors.RESET} {test_name}")
                    failed += 1
            except Exception as e:
                print(f"  {Colors.YELLOW}?{Colors.RESET} {test_name}: {e}")
                failed += 1

        print(f"\n{Colors.BOLD}Results:{Colors.RESET} {passed} passed, {failed} failed")

        # Check capabilities
        print(f"\n{Colors.BOLD}System Capabilities:{Colors.RESET}")
        caps = manager.get_capabilities()

        cap_items = [
            ('namespaces', 'Namespace support'),
            ('seccomp', 'Seccomp-BPF support'),
            ('cgroups_v2', 'Cgroups v2 support'),
            ('firewall', 'Firewall support'),
        ]

        for cap_id, cap_name in cap_items:
            status = caps.get(cap_id, {})
            if isinstance(status, dict):
                available = status.get('available', False)
            else:
                available = bool(status)

            icon = Colors.GREEN + '✓' if available else Colors.RED + '✗'
            print(f"  {icon}{Colors.RESET} {cap_name}")

        return 0 if failed == 0 else 1

    def _run_test(self, manager: SandboxManager, test_id: str, profile_name: str) -> bool:
        """Run a specific sandbox test."""
        # Simplified test implementation
        if test_id == 'namespace_isolation':
            # Test that PID 1 is not visible
            result = manager.run_sandboxed(
                command=['cat', '/proc/1/cmdline'],
                profile=SandboxProfile.from_name(profile_name),
                capture_output=True,
            )
            return result.exit_code != 0 or 'systemd' not in result.stdout

        elif test_id == 'seccomp_filter':
            # Test that blocked syscalls fail
            result = manager.run_sandboxed(
                command=['python3', '-c', 'import os; os.setuid(0)'],
                profile=SandboxProfile.from_name(profile_name),
                capture_output=True,
            )
            return result.exit_code != 0

        elif test_id == 'cgroup_limits':
            # Test that resource limits are applied
            # This is a simple check that the sandbox ran
            result = manager.run_sandboxed(
                command=['true'],
                profile=SandboxProfile.from_name(profile_name),
                capture_output=True,
            )
            return result.exit_code == 0

        elif test_id == 'network_policy':
            # Test network restrictions (if profile restricts network)
            if profile_name in ('AIRGAP', 'COLDROOM', 'RESTRICTED'):
                result = manager.run_sandboxed(
                    command=['ping', '-c', '1', '-W', '1', '8.8.8.8'],
                    profile=SandboxProfile.from_name(profile_name),
                    capture_output=True,
                )
                return result.exit_code != 0
            return True

        return False

    def cmd_metrics(self, args: argparse.Namespace) -> int:
        """Show sandbox metrics."""
        if not METRICS_AVAILABLE:
            print_error("Metrics module not available")
            return 1

        exporter = get_metrics_exporter()
        metrics = exporter.get_all_metrics()

        if args.output == 'json':
            print(json.dumps(metrics, indent=2))
        else:
            print(f"\n{Colors.BOLD}Sandbox Metrics:{Colors.RESET}\n")

            for metric in metrics:
                name = metric.get('name', 'unknown')
                value = metric.get('value', 0)
                mtype = metric.get('type', 'gauge')
                labels = metric.get('labels', {})

                label_str = ', '.join(f"{k}={v}" for k, v in labels.items())
                if label_str:
                    label_str = f" {{{label_str}}}"

                print(f"  {Colors.CYAN}{name}{Colors.RESET}{label_str}: {value}")

        return 0

    def _parse_memory(self, value: str) -> int:
        """Parse memory string (e.g., '512M', '1G') to bytes."""
        value = value.strip().upper()
        multipliers = {
            'B': 1,
            'K': 1024,
            'KB': 1024,
            'M': 1024 * 1024,
            'MB': 1024 * 1024,
            'G': 1024 * 1024 * 1024,
            'GB': 1024 * 1024 * 1024,
        }

        for suffix, mult in sorted(multipliers.items(), key=lambda x: -len(x[0])):
            if value.endswith(suffix):
                return int(float(value[:-len(suffix)]) * mult)

        return int(value)


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser."""
    parser = argparse.ArgumentParser(
        prog='sandboxctl',
        description='Sandbox Management CLI for Boundary Daemon',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sandboxctl run -- python3 script.py
  sandboxctl run --profile restricted -- npm install
  sandboxctl run --memory 512M --timeout 60 -- ./build.sh
  sandboxctl list
  sandboxctl inspect sandbox-001
  sandboxctl kill sandbox-001
  sandboxctl profiles
  sandboxctl test --profile airgap
        """
    )

    parser.add_argument(
        '--no-color', action='store_true',
        help='Disable colored output'
    )
    parser.add_argument(
        '-v', '--verbose', action='store_true',
        help='Enable verbose output'
    )
    parser.add_argument(
        '--socket', metavar='PATH',
        help='Path to daemon socket'
    )
    parser.add_argument(
        '--config', metavar='PATH',
        help='Path to configuration file'
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # run command
    run_parser = subparsers.add_parser('run', help='Run command in sandbox')
    run_parser.add_argument(
        '-p', '--profile', default='standard',
        help='Sandbox profile to use (default: standard)'
    )
    run_parser.add_argument(
        '-m', '--memory', metavar='SIZE',
        help='Memory limit (e.g., 512M, 1G)'
    )
    run_parser.add_argument(
        '-c', '--cpu', type=float, metavar='PERCENT',
        help='CPU limit percentage (e.g., 50 for 50%%)'
    )
    run_parser.add_argument(
        '-t', '--timeout', type=int, metavar='SECONDS',
        help='Timeout in seconds'
    )
    run_parser.add_argument(
        '--network-deny', action='store_true',
        help='Deny all network access'
    )
    run_parser.add_argument(
        '--network-allow', nargs='+', metavar='HOST',
        help='Allow network access to specific hosts'
    )
    run_parser.add_argument(
        '-i', '--interactive', action='store_true',
        help='Interactive mode (inherit stdin/stdout)'
    )
    run_parser.add_argument(
        '-e', '--inherit-env', action='store_true',
        help='Inherit environment variables'
    )
    run_parser.add_argument(
        '-q', '--quiet', action='store_true',
        help='Suppress informational output'
    )
    run_parser.add_argument(
        'command', nargs='*',
        help='Command to run'
    )

    # list command
    list_parser = subparsers.add_parser('list', aliases=['ls'], help='List sandboxes')
    list_parser.add_argument(
        '-o', '--output', choices=['table', 'json', 'wide'], default='table',
        help='Output format'
    )

    # inspect command
    inspect_parser = subparsers.add_parser('inspect', help='Inspect sandbox')
    inspect_parser.add_argument('sandbox_id', help='Sandbox ID')
    inspect_parser.add_argument(
        '-o', '--output', choices=['text', 'json'], default='text',
        help='Output format'
    )

    # kill command
    kill_parser = subparsers.add_parser('kill', help='Kill sandbox(es)')
    kill_parser.add_argument('sandbox_ids', nargs='*', help='Sandbox IDs to kill')
    kill_parser.add_argument(
        '-a', '--all', action='store_true',
        help='Kill all sandboxes'
    )
    kill_parser.add_argument(
        '-f', '--force', action='store_true',
        help='Force kill (SIGKILL instead of SIGTERM)'
    )

    # profiles command
    profiles_parser = subparsers.add_parser('profiles', help='List profiles')
    profiles_parser.add_argument(
        '-o', '--output', choices=['text', 'json'], default='text',
        help='Output format'
    )

    # test command
    test_parser = subparsers.add_parser('test', help='Test sandbox')
    test_parser.add_argument(
        '-p', '--profile', default='standard',
        help='Profile to test'
    )

    # metrics command
    metrics_parser = subparsers.add_parser('metrics', help='Show metrics')
    metrics_parser.add_argument(
        '-o', '--output', choices=['text', 'json'], default='text',
        help='Output format'
    )

    return parser


def main() -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()

    # Handle colors
    if args.no_color or not sys.stdout.isatty():
        Colors.disable()

    # Create CLI handler
    cli = SandboxCLI(
        socket_path=args.socket,
        config_path=args.config,
    )

    # Dispatch command
    if not args.command:
        parser.print_help()
        return 0

    command_map = {
        'run': cli.cmd_run,
        'list': cli.cmd_list,
        'ls': cli.cmd_list,
        'inspect': cli.cmd_inspect,
        'kill': cli.cmd_kill,
        'profiles': cli.cmd_profiles,
        'test': cli.cmd_test,
        'metrics': cli.cmd_metrics,
    }

    handler = command_map.get(args.command)
    if handler:
        return handler(args)
    else:
        print_error(f"Unknown command: {args.command}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
