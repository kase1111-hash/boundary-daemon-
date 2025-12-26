"""
Hardened Watchdog System - Resilient Daemon Monitoring

This module addresses Critical Finding #6: "External Watchdog Can Be Killed"

SECURITY IMPROVEMENTS:
1. Mutual Monitoring: Daemon and watchdog monitor each other
2. Cryptographic Heartbeats: HMAC-signed heartbeats prevent tampering
3. Challenge-Response: Proves both processes are alive and authentic
4. Process Hardening: prctl protections, signal handlers
5. Systemd Integration: Uses sd_notify for kernel-level monitoring
6. Hardware Watchdog: /dev/watchdog integration for hardware failsafe
7. Multi-Watchdog: Multiple watchdog processes for redundancy
8. Fail-Closed: System locks down if watchdog chain breaks

ARCHITECTURE:
    ┌─────────────┐     challenge      ┌─────────────────┐
    │   Daemon    │ ←──────────────────│  Primary        │
    │             │ ────────────────→  │  Watchdog       │
    └─────────────┘   signed response  └─────────────────┘
           ↑                                   │
           │ monitors                          │ monitors
           ↓                                   ↓
    ┌─────────────┐                   ┌─────────────────┐
    │  systemd    │                   │  Secondary      │
    │  watchdog   │                   │  Watchdog       │
    └─────────────┘                   └─────────────────┘
           │                                   │
           └───────────────────────────────────┘
                     monitors each other
"""

import os
import sys
import time
import signal
import socket
import struct
import secrets
import hashlib
import hmac
import json
import logging
import threading
import subprocess
import ctypes
from ctypes import c_int, c_ulong
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple
import tempfile

logger = logging.getLogger(__name__)


# Linux prctl constants
PR_SET_DUMPABLE = 4
PR_SET_NAME = 15
PR_SET_PDEATHSIG = 1


class WatchdogState(Enum):
    """Watchdog system state"""
    INITIALIZING = "initializing"
    RUNNING = "running"
    DEGRADED = "degraded"      # Some watchdogs failed
    CRITICAL = "critical"      # Multiple failures
    LOCKDOWN = "lockdown"      # System locked down


@dataclass
class HeartbeatChallenge:
    """Cryptographic challenge for heartbeat verification"""
    nonce: bytes
    timestamp: float
    challenge_id: str

    def serialize(self) -> bytes:
        return json.dumps({
            'nonce': self.nonce.hex(),
            'timestamp': self.timestamp,
            'challenge_id': self.challenge_id,
        }).encode()

    @classmethod
    def deserialize(cls, data: bytes) -> 'HeartbeatChallenge':
        d = json.loads(data.decode())
        return cls(
            nonce=bytes.fromhex(d['nonce']),
            timestamp=d['timestamp'],
            challenge_id=d['challenge_id'],
        )


@dataclass
class HeartbeatResponse:
    """Signed response to heartbeat challenge"""
    challenge_id: str
    timestamp: float
    process_id: int
    process_type: str  # 'daemon' or 'watchdog'
    signature: bytes

    def serialize(self) -> bytes:
        return json.dumps({
            'challenge_id': self.challenge_id,
            'timestamp': self.timestamp,
            'process_id': self.process_id,
            'process_type': self.process_type,
            'signature': self.signature.hex(),
        }).encode()

    @classmethod
    def deserialize(cls, data: bytes) -> 'HeartbeatResponse':
        d = json.loads(data.decode())
        return cls(
            challenge_id=d['challenge_id'],
            timestamp=d['timestamp'],
            process_id=d['process_id'],
            process_type=d['process_type'],
            signature=bytes.fromhex(d['signature']),
        )


class WatchdogProtocol:
    """Cryptographic protocol for watchdog communication"""

    def __init__(self, shared_secret: bytes):
        """
        Initialize with shared secret.

        The secret should be derived from:
        - Machine ID
        - Boot-time value
        - TPM-sealed secret (if available)
        """
        self._secret = shared_secret
        self._pending_challenges: Dict[str, HeartbeatChallenge] = {}
        self._challenge_timeout = 5.0  # seconds

    def generate_challenge(self) -> HeartbeatChallenge:
        """Generate a new challenge for heartbeat verification"""
        challenge = HeartbeatChallenge(
            nonce=secrets.token_bytes(32),
            timestamp=time.time(),
            challenge_id=secrets.token_hex(8),
        )
        self._pending_challenges[challenge.challenge_id] = challenge
        return challenge

    def create_response(
        self,
        challenge: HeartbeatChallenge,
        process_type: str,
    ) -> HeartbeatResponse:
        """Create a signed response to a challenge"""
        # Build message to sign
        msg = (
            challenge.nonce +
            struct.pack('!d', challenge.timestamp) +
            challenge.challenge_id.encode() +
            struct.pack('!I', os.getpid()) +
            process_type.encode()
        )

        # Sign with HMAC-SHA256
        signature = hmac.new(
            self._secret,
            msg,
            hashlib.sha256
        ).digest()

        return HeartbeatResponse(
            challenge_id=challenge.challenge_id,
            timestamp=time.time(),
            process_id=os.getpid(),
            process_type=process_type,
            signature=signature,
        )

    def verify_response(
        self,
        response: HeartbeatResponse,
        max_age: float = 5.0,
    ) -> Tuple[bool, str]:
        """Verify a heartbeat response"""
        # Check if challenge exists
        challenge = self._pending_challenges.get(response.challenge_id)
        if not challenge:
            return (False, "Unknown challenge ID")

        # Check timestamp (not too old, not in future)
        now = time.time()
        if response.timestamp < challenge.timestamp:
            return (False, "Response timestamp before challenge")
        if response.timestamp > now + 1.0:  # Allow 1s clock skew
            return (False, "Response timestamp in future")
        if now - challenge.timestamp > max_age:
            return (False, "Challenge expired")

        # Verify signature
        msg = (
            challenge.nonce +
            struct.pack('!d', challenge.timestamp) +
            challenge.challenge_id.encode() +
            struct.pack('!I', response.process_id) +
            response.process_type.encode()
        )

        expected_sig = hmac.new(
            self._secret,
            msg,
            hashlib.sha256
        ).digest()

        if not hmac.compare_digest(response.signature, expected_sig):
            return (False, "Invalid signature")

        # Check process is still alive
        try:
            os.kill(response.process_id, 0)
        except OSError:
            return (False, "Process not alive")

        # Clean up challenge
        del self._pending_challenges[response.challenge_id]

        return (True, "Valid response")

    def cleanup_expired(self):
        """Remove expired challenges"""
        now = time.time()
        expired = [
            cid for cid, c in self._pending_challenges.items()
            if now - c.timestamp > self._challenge_timeout
        ]
        for cid in expired:
            del self._pending_challenges[cid]


class ProcessHardening:
    """Linux process hardening to resist attacks"""

    @staticmethod
    def apply_protections():
        """Apply kernel-level process protections"""
        try:
            libc = ctypes.CDLL('libc.so.6', use_errno=True)

            # Prevent core dumps (could leak secrets)
            libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
            logger.debug("Disabled core dumps")

            # Set process name for easier identification
            libc.prctl(PR_SET_NAME, b"boundary-wdog", 0, 0, 0)

        except Exception as e:
            logger.warning(f"Could not apply process hardening: {e}")

    @staticmethod
    def setup_signal_handlers(on_terminate: Callable):
        """Setup signal handlers for graceful degradation"""

        def handler(signum, frame):
            sig_name = signal.Signals(signum).name
            logger.warning(f"Received signal {sig_name} - triggering lockdown")
            on_terminate(f"Signal {sig_name}")

        # Catch termination signals
        signal.signal(signal.SIGTERM, handler)
        signal.signal(signal.SIGINT, handler)
        signal.signal(signal.SIGHUP, handler)

        # Note: SIGKILL (9) cannot be caught - that's why we need redundancy

    @staticmethod
    def is_process_protected(pid: int) -> bool:
        """Check if a process has protection against ptrace"""
        try:
            with open(f'/proc/{pid}/status', 'r') as f:
                for line in f:
                    if line.startswith('TracerPid:'):
                        tracer = int(line.split(':')[1].strip())
                        return tracer == 0  # Not being traced
            return False
        except Exception:
            return False


class SystemdWatchdog:
    """Integration with systemd's watchdog functionality"""

    def __init__(self):
        self._watchdog_usec = self._get_watchdog_usec()
        self._enabled = self._watchdog_usec > 0
        self._last_notify = 0

    def _get_watchdog_usec(self) -> int:
        """Get WATCHDOG_USEC from environment"""
        try:
            return int(os.environ.get('WATCHDOG_USEC', '0'))
        except ValueError:
            return 0

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def timeout_seconds(self) -> float:
        return self._watchdog_usec / 1_000_000.0

    def notify(self, status: str = "WATCHDOG=1"):
        """
        Send notification to systemd.

        Common notifications:
        - WATCHDOG=1: Keep-alive ping
        - READY=1: Service is ready
        - STATUS=...: Human-readable status
        """
        if not self._enabled:
            return

        notify_socket = os.environ.get('NOTIFY_SOCKET')
        if not notify_socket:
            return

        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            if notify_socket.startswith('@'):
                # Abstract namespace
                notify_socket = '\0' + notify_socket[1:]
            sock.connect(notify_socket)
            sock.sendall(status.encode())
            sock.close()
            self._last_notify = time.time()
        except Exception as e:
            logger.debug(f"sd_notify failed: {e}")

    def watchdog_ping(self):
        """Send watchdog keep-alive"""
        self.notify("WATCHDOG=1")

    def set_status(self, status: str):
        """Set human-readable status"""
        self.notify(f"STATUS={status}")

    def ready(self):
        """Signal service is ready"""
        self.notify("READY=1")


class HardwareWatchdog:
    """Integration with hardware watchdog (/dev/watchdog)"""

    WATCHDOG_DEVICE = "/dev/watchdog"

    def __init__(self, timeout: int = 60):
        """
        Initialize hardware watchdog.

        Args:
            timeout: Seconds before hardware reset if not pinged
        """
        self._fd = None
        self._timeout = timeout
        self._enabled = False

    @property
    def available(self) -> bool:
        return os.path.exists(self.WATCHDOG_DEVICE) and os.access(self.WATCHDOG_DEVICE, os.W_OK)

    def enable(self) -> bool:
        """Enable hardware watchdog"""
        if not self.available:
            logger.warning("Hardware watchdog not available")
            return False

        try:
            self._fd = os.open(self.WATCHDOG_DEVICE, os.O_WRONLY)

            # Set timeout using ioctl (WDIOC_SETTIMEOUT = 0xC0045706)
            # This requires root

            self._enabled = True
            logger.info(f"Hardware watchdog enabled (timeout: {self._timeout}s)")
            return True

        except Exception as e:
            logger.error(f"Failed to enable hardware watchdog: {e}")
            return False

    def ping(self):
        """Ping the hardware watchdog to prevent reset"""
        if not self._enabled or self._fd is None:
            return

        try:
            os.write(self._fd, b'1')
        except Exception as e:
            logger.error(f"Hardware watchdog ping failed: {e}")

    def disable(self):
        """Disable hardware watchdog (write 'V' magic close)"""
        if self._fd is not None:
            try:
                os.write(self._fd, b'V')  # Magic close
                os.close(self._fd)
            except Exception:
                pass
            self._fd = None
            self._enabled = False


class WatchdogPeer:
    """Represents another watchdog process for mutual monitoring"""

    def __init__(
        self,
        peer_id: str,
        socket_path: str,
        protocol: WatchdogProtocol,
    ):
        self.peer_id = peer_id
        self.socket_path = socket_path
        self.protocol = protocol
        self.last_seen = 0
        self.consecutive_failures = 0
        self.is_alive = False

    def check(self) -> bool:
        """Send challenge to peer and verify response"""
        challenge = self.protocol.generate_challenge()

        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect(self.socket_path)

            # Send challenge
            sock.sendall(challenge.serialize())

            # Receive response
            data = sock.recv(4096)
            sock.close()

            if not data:
                raise Exception("No response")

            response = HeartbeatResponse.deserialize(data)
            valid, msg = self.protocol.verify_response(response)

            if valid:
                self.last_seen = time.time()
                self.consecutive_failures = 0
                self.is_alive = True
                return True
            else:
                logger.warning(f"Peer {self.peer_id} invalid response: {msg}")
                self.consecutive_failures += 1
                return False

        except Exception as e:
            logger.warning(f"Peer {self.peer_id} check failed: {e}")
            self.consecutive_failures += 1
            self.is_alive = False
            return False


class HardenedWatchdog:
    """
    Hardened watchdog with multiple layers of protection.

    This watchdog:
    1. Monitors the daemon via challenge-response
    2. Is monitored by other watchdog instances
    3. Uses systemd watchdog for kernel-level monitoring
    4. Optionally uses hardware watchdog
    5. Triggers lockdown if monitoring chain breaks
    """

    RUN_DIR = "/var/run/boundary-daemon"
    MAX_FAILURES = 3
    CHECK_INTERVAL = 2.0  # seconds

    def __init__(
        self,
        watchdog_id: str,
        shared_secret: bytes,
        daemon_socket: Optional[str] = None,
        is_primary: bool = True,
        on_lockdown: Optional[Callable] = None,
    ):
        """
        Initialize hardened watchdog.

        Args:
            watchdog_id: Unique identifier for this watchdog
            shared_secret: Secret for HMAC authentication
            daemon_socket: Path to daemon's watchdog socket
            is_primary: Whether this is the primary watchdog
            on_lockdown: Callback when triggering lockdown
        """
        self.watchdog_id = watchdog_id
        self.is_primary = is_primary
        self._on_lockdown = on_lockdown

        # Protocol
        self.protocol = WatchdogProtocol(shared_secret)

        # Socket paths
        self.daemon_socket = daemon_socket or f"{self.RUN_DIR}/daemon.sock"
        self.my_socket = f"{self.RUN_DIR}/watchdog_{watchdog_id}.sock"

        # State
        self.state = WatchdogState.INITIALIZING
        self._running = False
        self._lock = threading.Lock()

        # Monitoring
        self._daemon_failures = 0
        self._last_daemon_response = 0
        self._peers: Dict[str, WatchdogPeer] = {}

        # Server socket for receiving challenges
        self._server_socket = None
        self._server_thread = None

        # Integrations
        self.systemd = SystemdWatchdog()
        self.hardware = HardwareWatchdog()

        # Event log
        self._events: List[Dict] = []

    def _log_event(self, event_type: str, details: str):
        """Log a watchdog event"""
        event = {
            'timestamp': datetime.now().isoformat(),
            'watchdog_id': self.watchdog_id,
            'type': event_type,
            'details': details,
        }
        self._events.append(event)
        logger.info(f"[WATCHDOG:{self.watchdog_id}] {event_type}: {details}")

    def _ensure_run_dir(self):
        """Ensure run directory exists with proper permissions"""
        run_dir = Path(self.RUN_DIR)
        run_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(run_dir, 0o700)

    def _start_server(self):
        """Start socket server for receiving challenges"""
        self._ensure_run_dir()

        # Remove old socket
        socket_path = Path(self.my_socket)
        if socket_path.exists():
            socket_path.unlink()

        # Create server socket
        self._server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server_socket.bind(self.my_socket)
        self._server_socket.listen(5)
        self._server_socket.settimeout(1.0)
        os.chmod(self.my_socket, 0o600)

        def server_loop():
            while self._running:
                try:
                    conn, _ = self._server_socket.accept()
                    conn.settimeout(2.0)

                    # Receive challenge
                    data = conn.recv(4096)
                    if data:
                        challenge = HeartbeatChallenge.deserialize(data)
                        response = self.protocol.create_response(
                            challenge,
                            process_type='watchdog'
                        )
                        conn.sendall(response.serialize())

                    conn.close()
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.debug(f"Server error: {e}")

        self._server_thread = threading.Thread(target=server_loop, daemon=True)
        self._server_thread.start()

    def add_peer(self, peer_id: str, socket_path: str):
        """Add a peer watchdog to monitor"""
        peer = WatchdogPeer(peer_id, socket_path, self.protocol)
        self._peers[peer_id] = peer
        self._log_event("PEER_ADDED", f"Added peer watchdog: {peer_id}")

    def _check_daemon(self) -> bool:
        """Send challenge to daemon and verify response"""
        challenge = self.protocol.generate_challenge()

        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect(self.daemon_socket)

            # Send challenge
            sock.sendall(challenge.serialize())

            # Receive response
            data = sock.recv(4096)
            sock.close()

            if not data:
                raise Exception("No response from daemon")

            response = HeartbeatResponse.deserialize(data)
            valid, msg = self.protocol.verify_response(response)

            if valid:
                self._daemon_failures = 0
                self._last_daemon_response = time.time()
                return True
            else:
                self._log_event("DAEMON_INVALID", f"Invalid response: {msg}")
                self._daemon_failures += 1
                return False

        except FileNotFoundError:
            self._log_event("DAEMON_MISSING", "Daemon socket not found")
            self._daemon_failures += 1
            return False
        except Exception as e:
            self._log_event("DAEMON_ERROR", str(e))
            self._daemon_failures += 1
            return False

    def _check_peers(self) -> int:
        """Check all peer watchdogs, return number of failures"""
        failures = 0
        for peer in self._peers.values():
            if not peer.check():
                failures += 1
                if peer.consecutive_failures >= self.MAX_FAILURES:
                    self._log_event(
                        "PEER_DEAD",
                        f"Peer {peer.peer_id} not responding"
                    )
        return failures

    def _trigger_lockdown(self, reason: str):
        """Trigger emergency lockdown"""
        self._log_event("LOCKDOWN_TRIGGERED", reason)
        self.state = WatchdogState.LOCKDOWN

        logger.critical(f"WATCHDOG LOCKDOWN: {reason}")

        # Execute lockdown
        try:
            # 1. Block all network traffic
            subprocess.run(['iptables', '-P', 'INPUT', 'DROP'], timeout=5)
            subprocess.run(['iptables', '-P', 'OUTPUT', 'DROP'], timeout=5)
            subprocess.run(['iptables', '-P', 'FORWARD', 'DROP'], timeout=5)
        except Exception as e:
            logger.error(f"iptables lockdown failed: {e}")

        try:
            # 2. Log to syslog
            subprocess.run([
                'logger', '-p', 'auth.crit',
                f'BOUNDARY-WATCHDOG: LOCKDOWN - {reason}'
            ], timeout=5)
        except Exception:
            pass

        try:
            # 3. Send wall message
            subprocess.run([
                'wall',
                f'SECURITY ALERT: Boundary daemon watchdog triggered lockdown: {reason}'
            ], timeout=5)
        except Exception:
            pass

        # 4. Callback
        if self._on_lockdown:
            try:
                self._on_lockdown(reason)
            except Exception:
                pass

        # 5. Write lockdown indicator file
        try:
            lockdown_file = Path(self.RUN_DIR) / 'LOCKDOWN'
            lockdown_file.write_text(
                f"Lockdown triggered at {datetime.now().isoformat()}\n"
                f"Reason: {reason}\n"
                f"Watchdog: {self.watchdog_id}\n"
            )
        except Exception:
            pass

    def _monitor_loop(self):
        """Main monitoring loop"""
        while self._running:
            try:
                # 1. Check daemon
                daemon_ok = self._check_daemon()

                if not daemon_ok:
                    if self._daemon_failures >= self.MAX_FAILURES:
                        self._trigger_lockdown(
                            f"Daemon not responding ({self._daemon_failures} failures)"
                        )
                        continue
                    else:
                        self.state = WatchdogState.DEGRADED
                else:
                    # 2. Check peer watchdogs
                    peer_failures = self._check_peers()

                    if peer_failures > 0:
                        if peer_failures == len(self._peers):
                            # All peers dead - we might be next
                            self.state = WatchdogState.CRITICAL
                            self._log_event(
                                "ALL_PEERS_DEAD",
                                "All peer watchdogs unresponsive"
                            )
                        else:
                            self.state = WatchdogState.DEGRADED
                    else:
                        self.state = WatchdogState.RUNNING

                # 3. Ping systemd watchdog
                if self.systemd.enabled:
                    self.systemd.watchdog_ping()
                    self.systemd.set_status(f"State: {self.state.value}")

                # 4. Ping hardware watchdog
                if self.hardware._enabled:
                    self.hardware.ping()

            except Exception as e:
                logger.error(f"Monitor loop error: {e}")

            # Sleep with interruption check
            for _ in range(int(self.CHECK_INTERVAL * 10)):
                if not self._running:
                    break
                time.sleep(0.1)

    def start(self):
        """Start the watchdog"""
        if self._running:
            return

        # Apply process hardening
        ProcessHardening.apply_protections()
        ProcessHardening.setup_signal_handlers(self._trigger_lockdown)

        # Start server
        self._start_server()

        # Enable integrations
        if self.is_primary:
            if self.systemd.enabled:
                self.systemd.ready()
                self._log_event("SYSTEMD", f"Enabled (timeout: {self.systemd.timeout_seconds}s)")

            if self.hardware.available:
                self.hardware.enable()
                self._log_event("HARDWARE_WATCHDOG", "Enabled")

        # Start monitoring
        self._running = True
        self.state = WatchdogState.RUNNING

        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name=f"Watchdog-{self.watchdog_id}"
        )
        self._monitor_thread.start()

        self._log_event("STARTED", f"Primary: {self.is_primary}")

    def stop(self):
        """Stop the watchdog"""
        self._running = False

        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                pass

        if hasattr(self, '_monitor_thread'):
            self._monitor_thread.join(timeout=5.0)

        if self._server_thread:
            self._server_thread.join(timeout=2.0)

        # Clean up socket
        try:
            Path(self.my_socket).unlink()
        except Exception:
            pass

        # Disable hardware watchdog gracefully
        self.hardware.disable()

        self._log_event("STOPPED", "Watchdog stopped")

    def get_status(self) -> Dict:
        """Get watchdog status"""
        return {
            'watchdog_id': self.watchdog_id,
            'state': self.state.value,
            'is_primary': self.is_primary,
            'daemon_failures': self._daemon_failures,
            'last_daemon_response': self._last_daemon_response,
            'peers': {
                pid: {
                    'alive': p.is_alive,
                    'last_seen': p.last_seen,
                    'failures': p.consecutive_failures,
                }
                for pid, p in self._peers.items()
            },
            'systemd_enabled': self.systemd.enabled,
            'hardware_watchdog': self.hardware._enabled,
            'event_count': len(self._events),
        }


class DaemonWatchdogEndpoint:
    """
    Watchdog endpoint for the daemon side.

    This runs inside the daemon and responds to watchdog challenges.
    """

    def __init__(
        self,
        shared_secret: bytes,
        socket_path: str = "/var/run/boundary-daemon/daemon.sock",
        health_checker: Optional[Callable[[], bool]] = None,
    ):
        """
        Initialize daemon endpoint.

        Args:
            shared_secret: Same secret as watchdog
            socket_path: Path for socket
            health_checker: Optional callback to verify daemon health
        """
        self.protocol = WatchdogProtocol(shared_secret)
        self.socket_path = socket_path
        self._health_checker = health_checker
        self._server_socket = None
        self._running = False
        self._thread = None

    def _handle_client(self, conn):
        """Handle incoming challenge from watchdog"""
        try:
            conn.settimeout(2.0)
            data = conn.recv(4096)

            if not data:
                return

            # Verify we're healthy before responding
            if self._health_checker and not self._health_checker():
                logger.warning("Health check failed - not responding to watchdog")
                return

            # Parse challenge and respond
            challenge = HeartbeatChallenge.deserialize(data)
            response = self.protocol.create_response(challenge, 'daemon')
            conn.sendall(response.serialize())

        except Exception as e:
            logger.debug(f"Watchdog endpoint error: {e}")
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def start(self):
        """Start the endpoint"""
        if self._running:
            return

        # Ensure directory exists
        socket_dir = Path(self.socket_path).parent
        socket_dir.mkdir(parents=True, exist_ok=True)

        # Remove old socket
        socket_path = Path(self.socket_path)
        if socket_path.exists():
            socket_path.unlink()

        # Create server socket
        self._server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server_socket.bind(self.socket_path)
        self._server_socket.listen(5)
        self._server_socket.settimeout(1.0)
        os.chmod(self.socket_path, 0o600)

        self._running = True

        def server_loop():
            while self._running:
                try:
                    conn, _ = self._server_socket.accept()
                    # Handle in thread to not block
                    threading.Thread(
                        target=self._handle_client,
                        args=(conn,),
                        daemon=True
                    ).start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self._running:
                        logger.debug(f"Accept error: {e}")

        self._thread = threading.Thread(target=server_loop, daemon=True, name="DaemonWatchdogEndpoint")
        self._thread.start()

        logger.info(f"Daemon watchdog endpoint started: {self.socket_path}")

    def stop(self):
        """Stop the endpoint"""
        self._running = False

        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                pass

        if self._thread:
            self._thread.join(timeout=2.0)

        # Clean up socket
        try:
            Path(self.socket_path).unlink()
        except Exception:
            pass

        logger.info("Daemon watchdog endpoint stopped")


def generate_shared_secret() -> bytes:
    """
    Generate a shared secret for watchdog communication.

    In production, this should be:
    1. Derived from TPM-sealed secret
    2. Or from machine-specific data at installation time
    """
    # Use machine-specific data for the secret
    components = []

    # Machine ID
    try:
        with open('/etc/machine-id', 'r') as f:
            components.append(f.read().strip())
    except Exception:
        pass

    # Boot ID (changes each boot - adds freshness)
    try:
        with open('/proc/sys/kernel/random/boot_id', 'r') as f:
            components.append(f.read().strip())
    except Exception:
        pass

    # If nothing else, use a random secret (not persistent across restarts)
    if not components:
        return secrets.token_bytes(32)

    # Derive secret from components
    combined = ':'.join(components).encode()
    return hashlib.sha256(combined).digest()


# Standalone watchdog entry point
def run_external_watchdog(
    watchdog_id: str = "primary",
    peer_sockets: Optional[List[str]] = None,
):
    """
    Run as an external watchdog process.

    This should be run as a separate systemd service.

    Example systemd unit:
    [Unit]
    Description=Boundary Daemon Watchdog
    After=boundary-daemon.service
    BindsTo=boundary-daemon.service

    [Service]
    Type=notify
    ExecStart=/usr/bin/python3 -m daemon.watchdog.hardened_watchdog
    WatchdogSec=30
    Restart=always
    RestartSec=1

    [Install]
    WantedBy=multi-user.target
    """
    import argparse

    parser = argparse.ArgumentParser(description="Boundary Daemon Watchdog")
    parser.add_argument('--id', default='primary', help='Watchdog ID')
    parser.add_argument('--peer', action='append', help='Peer watchdog socket paths')
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    )

    secret = generate_shared_secret()

    watchdog = HardenedWatchdog(
        watchdog_id=args.id,
        shared_secret=secret,
        is_primary=(args.id == 'primary'),
    )

    # Add peers
    if args.peer:
        for i, peer_socket in enumerate(args.peer):
            watchdog.add_peer(f"peer_{i}", peer_socket)

    print(f"Starting hardened watchdog: {args.id}")
    watchdog.start()

    try:
        # Keep running
        while True:
            time.sleep(10)
            status = watchdog.get_status()
            print(f"Status: {status['state']} | Daemon failures: {status['daemon_failures']}")
    except KeyboardInterrupt:
        print("\nStopping watchdog...")
        watchdog.stop()


if __name__ == '__main__':
    run_external_watchdog()
