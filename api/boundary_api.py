"""
Boundary API - Unix Socket Interface
Provides local-only socket API for other Agent OS components.

Security Features:
- Token-based authentication
- Capability-based access control
- Per-token rate limiting
- Request logging
"""

import json
import logging
import os
import socket
import sys
import threading
import time
from datetime import datetime
from typing import Optional, Dict, Any, TYPE_CHECKING

logger = logging.getLogger(__name__)

# Import error handling framework for consistent error management
try:
    from daemon.utils.error_handling import (
        log_security_error,
        log_auth_error,
        log_network_error,
    )
    ERROR_HANDLING_AVAILABLE = True
except ImportError:
    ERROR_HANDLING_AVAILABLE = False
    def log_security_error(e, op, **ctx):
        logger.error(f"SECURITY: {op}: {e}")
    def log_auth_error(e, op, **ctx):
        logger.error(f"AUTH: {op}: {e}")
    def log_network_error(e, op, **ctx):
        logger.error(f"NETWORK: {op}: {e}")

# Cross-platform socket support
IS_WINDOWS = sys.platform == 'win32'
HAS_UNIX_SOCKETS = hasattr(socket, 'AF_UNIX')

if TYPE_CHECKING:
    from daemon.telemetry import TelemetryManager

from daemon.policy_engine import BoundaryMode, Operator, MemoryClass
from daemon.auth.api_auth import (
    TokenManager,
    AuthenticationMiddleware,
)


class BoundaryAPIServer:
    """
    Unix socket API server for boundary daemon.
    Provides authenticated API with capability-based access control.

    Authentication:
        All requests must include a 'token' field with a valid API token.
        Tokens are created using the 'create_token' command or authctl CLI.

    Rate Limiting:
        Each token is rate-limited to prevent abuse.
        Default: 100 requests per 60 seconds.
    """

    def __init__(
        self,
        daemon,
        socket_path: str = './api/boundary.sock',
        token_file: str = './config/api_tokens.json',
        require_auth: bool = True,
        rate_limit_window: int = 60,
        rate_limit_max_requests: int = 100,
        telemetry_manager: Optional['TelemetryManager'] = None,
    ):
        """
        Initialize API server.

        Args:
            daemon: Reference to BoundaryDaemon instance
            socket_path: Path to Unix socket
            token_file: Path to token storage file
            require_auth: Whether authentication is required
            rate_limit_window: Rate limit window in seconds
            rate_limit_max_requests: Max requests per window
            telemetry_manager: TelemetryManager for latency recording (optional)
        """
        self.daemon = daemon
        self.socket_path = socket_path
        self.require_auth = require_auth
        self._running = False
        self._server_thread: Optional[threading.Thread] = None
        self._socket: Optional[socket.socket] = None

        # Ingestion stats tracking (for SIEM clients pulling events)
        self._ingestion_stats = {
            'total_requests': 0,
            'total_events_served': 0,
            'last_request_time': None,
            'last_request_timestamp': None,  # Unix timestamp for timeout check
            'last_client': None,
            'requests_today': 0,
            'events_today': 0,
            'today_date': None,
            'connected': False,  # True if SIEM has connected within timeout
            'was_connected': False,  # Track previous state for disconnect detection
        }
        self._ingestion_lock = threading.Lock()
        self._ingestion_timeout = 60.0  # Consider disconnected after 60 seconds of no requests

        # Telemetry integration for API latency monitoring (Plan 11)
        self._telemetry_manager: Optional['TelemetryManager'] = telemetry_manager

        # Initialize authentication
        # Get event logger from daemon if available
        event_logger = getattr(daemon, 'event_logger', None) if daemon else None

        self.token_manager = TokenManager(
            token_file=token_file,
            rate_limit_window=rate_limit_window,
            rate_limit_max_requests=rate_limit_max_requests,
            event_logger=event_logger,
        )
        self.auth_middleware = AuthenticationMiddleware(
            token_manager=self.token_manager,
            require_auth=require_auth,
        )

        # Ensure directory exists
        os.makedirs(os.path.dirname(socket_path), exist_ok=True)

        # Remove stale socket (Unix only)
        if HAS_UNIX_SOCKETS and not IS_WINDOWS:
            if os.path.exists(socket_path):
                os.unlink(socket_path)

    def start(self):
        """Start the API server"""
        if self._running:
            return

        self._running = True
        self._server_thread = threading.Thread(target=self._server_loop, daemon=True)
        self._server_thread.start()
        print(f"Boundary API server listening on {self.socket_path}")

    def stop(self):
        """Stop the API server"""
        if not self._running:
            return

        self._running = False

        # Close socket
        if self._socket:
            self._socket.close()

        # Wait for thread
        if self._server_thread:
            self._server_thread.join(timeout=5.0)

        # Remove socket file (Unix only)
        if HAS_UNIX_SOCKETS and not IS_WINDOWS:
            if os.path.exists(self.socket_path):
                os.unlink(self.socket_path)

    def set_telemetry_manager(self, telemetry_manager: 'TelemetryManager'):
        """
        Set the telemetry manager for API latency recording.

        This allows setting telemetry after initialization, useful when
        the telemetry system is initialized after the API server.

        Args:
            telemetry_manager: TelemetryManager instance for recording latency
        """
        self._telemetry_manager = telemetry_manager

    def _record_latency(self, command: str, latency_ms: float, success: bool):
        """
        Record API call latency to telemetry.

        Args:
            command: The API command that was executed
            latency_ms: Time taken in milliseconds
            success: Whether the request was successful
        """
        if self._telemetry_manager:
            try:
                self._telemetry_manager.record_api_latency(
                    endpoint=command or 'unknown',
                    method='UNIX_SOCKET',
                    latency_ms=latency_ms,
                    success=success,
                )
            except Exception as telemetry_err:
                # Don't fail requests due to telemetry errors, but log for debugging
                logger.debug(f"Telemetry recording failed: {telemetry_err}")

    def _server_loop(self):
        """Main server loop"""
        try:
            # Create socket (cross-platform)
            if HAS_UNIX_SOCKETS and not IS_WINDOWS:
                # Unix domain socket (Linux/macOS)
                self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self._socket.bind(self.socket_path)
                self._socket.listen(5)
                # Set permissions (owner only)
                os.chmod(self.socket_path, 0o600)
            else:
                # TCP socket on localhost (Windows)
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # Use port 19847 for the API (configurable via socket_path parsing)
                self._tcp_port = 19847
                self._socket.bind(('127.0.0.1', self._tcp_port))
                self._socket.listen(5)

            while self._running:
                try:
                    # Accept connection with timeout
                    self._socket.settimeout(1.0)
                    try:
                        conn, _ = self._socket.accept()
                    except socket.timeout:
                        continue

                    # Handle request in a new thread
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(conn,),
                        daemon=True
                    )
                    client_thread.start()

                except (OSError, socket.error, ConnectionError) as e:
                    # Socket-level errors during accept/client handling
                    if self._running:
                        log_network_error(e, "api_server_loop", socket_path=self.socket_path)

        except (OSError, socket.error, PermissionError) as e:
            # Fatal socket binding/setup errors
            log_network_error(e, "api_server_fatal", socket_path=self.socket_path)
            logger.critical(f"Fatal error in API server: {e}")
        finally:
            if self._socket:
                self._socket.close()

    def _handle_client(self, conn: socket.socket):
        """Handle a client connection with latency tracking"""
        start_time = time.monotonic()
        command = None
        success = False

        try:
            # Read request (max 4KB)
            data = conn.recv(4096)
            if not data:
                return

            # Parse JSON request
            try:
                request = json.loads(data.decode('utf-8'))
                command = request.get('command', 'unknown')
            except json.JSONDecodeError:
                command = 'invalid_json'
                response = {'error': 'Invalid JSON'}
                conn.sendall(json.dumps(response).encode('utf-8'))
                return

            # Process request
            response = self._process_request(request)

            # Check if request was successful
            success = response.get('success', False) or 'error' not in response

            # Send response
            conn.sendall(json.dumps(response).encode('utf-8'))

        except Exception as e:
            error_response = {'error': str(e)}
            try:
                conn.sendall(json.dumps(error_response).encode('utf-8'))
            except (OSError, socket.error, BrokenPipeError) as send_err:
                # Client disconnected or socket error - log at debug level
                logger.debug(f"Failed to send error response to client: {send_err}")
        finally:
            # Record latency (Plan 11: API Latency Monitoring)
            elapsed_ms = (time.monotonic() - start_time) * 1000
            self._record_latency(command, elapsed_ms, success)
            conn.close()

    def _process_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process an API request.

        Request format:
        {
            "command": "status|check_recall|check_tool|set_mode|get_events|verify_log|...",
            "token": "<api_token>",
            "params": {...}
        }

        Token Management Commands (require MANAGE_TOKENS capability):
        - create_token: Create a new API token
        - revoke_token: Revoke an existing token
        - list_tokens: List all tokens

        Response includes rate limit headers:
        - rate_limit: Per-token rate limit info
        - rate_limit.X-RateLimit-Limit: Max requests per window
        - rate_limit.X-RateLimit-Remaining: Requests remaining
        - rate_limit.X-RateLimit-Reset: Seconds until reset
        """
        command = request.get('command')
        params = request.get('params', {})

        # Commands that don't require authentication (read-only, safe to expose)
        # These are used by the TUI dashboard for display purposes
        PUBLIC_COMMANDS = {
            'status',           # Daemon status (mode, uptime, etc.)
            'ping',             # Health check
            'version',          # Version info
            'get_events',       # Event log (read-only)
            'get_alerts',       # Active alerts (read-only)
            'get_sandboxes',    # Sandbox status (read-only)
            'get_siem_status',  # SIEM shipping status (read-only)
            'create_tui_token', # Auto-create limited TUI token (one-time setup)
        }

        # Skip authentication for public commands
        if command in PUBLIC_COMMANDS:
            # Process without token
            response = self._dispatch_command(command, params, None)
            return response

        # Authenticate request for all other commands
        is_authorized, token, auth_message = self.auth_middleware.authenticate_request(request)

        if not is_authorized:
            return {
                'success': False,
                'error': f'Authentication failed: {auth_message}',
                'auth_error': True,
            }

        # Log authenticated request (if we have event logger)
        if token and hasattr(self.daemon, 'event_logger'):
            try:
                from daemon.event_logger import EventType
                self.daemon.event_logger.log_event(
                    event_type=EventType.API_REQUEST,
                    data={
                        'command': command,
                        'token_id': token.token_id,
                        'token_name': token.name,
                    }
                )
            except Exception as log_err:
                # Don't fail request on logging error, but record for debugging
                logger.debug(f"API request logging failed: {log_err}")

        # Process command and get response
        response = self._dispatch_command(command, params, token)

        # Add rate limit headers to response
        if token:
            response['rate_limit'] = self.token_manager.get_rate_limit_headers(
                token.token_id, command
            )

        return response

    def _dispatch_command(
        self,
        command: str,
        params: Dict[str, Any],
        token: Any
    ) -> Dict[str, Any]:
        """Dispatch command to appropriate handler."""
        # Handle token management commands
        if command == 'create_token':
            return self._handle_create_token(params, token)
        elif command == 'create_tui_token':
            return self._handle_create_tui_token(params)
        elif command == 'revoke_token':
            return self._handle_revoke_token(params, token)
        elif command == 'list_tokens':
            return self._handle_list_tokens(params)
        elif command == 'rate_limit_status':
            return self._handle_rate_limit_status(params)

        if command == 'status':
            return self._handle_status()

        elif command == 'check_recall':
            return self._handle_check_recall(params)

        elif command == 'check_tool':
            return self._handle_check_tool(params)

        elif command == 'set_mode':
            return self._handle_set_mode(params)

        elif command == 'get_events':
            return self._handle_get_events(params)

        elif command == 'verify_log':
            return self._handle_verify_log()

        elif command == 'check_message':
            return self._handle_check_message(params)

        elif command == 'check_natlangchain':
            return self._handle_check_natlangchain(params)

        elif command == 'check_agentos':
            return self._handle_check_agentos(params)

        # Monitoring commands (Plan 11)
        elif command == 'get_memory_stats':
            return self._handle_get_memory_stats()

        elif command == 'toggle_memory_debug':
            return self._handle_toggle_memory_debug()

        elif command == 'get_resource_stats':
            return self._handle_get_resource_stats()

        elif command == 'get_health_stats':
            return self._handle_get_health_stats()

        elif command == 'get_queue_stats':
            return self._handle_get_queue_stats()

        elif command == 'get_monitoring_summary':
            return self._handle_get_monitoring_summary()

        # Report generation commands (Plan 11)
        elif command == 'generate_report':
            return self._handle_generate_report(params)

        elif command == 'get_raw_report':
            return self._handle_get_raw_report(params)

        elif command == 'check_ollama_status':
            return self._handle_check_ollama_status()

        elif command == 'get_report_history':
            return self._handle_get_report_history(params)

        elif command == 'query':
            return self._handle_query(params)

        # Dashboard commands
        elif command == 'get_alerts':
            return self._handle_get_alerts(params)

        elif command == 'get_sandboxes':
            return self._handle_get_sandboxes()

        elif command == 'get_siem_status':
            return self._handle_get_siem_status()

        else:
            return {'error': f'Unknown command: {command}'}

    def _handle_create_token(self, params: Dict[str, Any], requesting_token) -> Dict[str, Any]:
        """
        Create a new API token.

        Params:
            name: str - Human-readable name for the token
            capabilities: list - List of capabilities or capability set name
            expires_in_days: int (optional) - Days until expiration (default: 365)
            metadata: dict (optional) - Additional metadata
        """
        try:
            name = params.get('name')
            capabilities = params.get('capabilities')

            if not name:
                return {'success': False, 'error': 'name parameter required'}
            if not capabilities:
                return {'success': False, 'error': 'capabilities parameter required'}

            expires_in_days = params.get('expires_in_days', 365)
            metadata = params.get('metadata', {})

            # Convert capabilities to set
            if isinstance(capabilities, str):
                capabilities = {capabilities}
            else:
                capabilities = set(capabilities)

            # Create token
            raw_token, token_obj = self.token_manager.create_token(
                name=name,
                capabilities=capabilities,
                created_by=requesting_token.name if requesting_token else 'system',
                expires_in_days=expires_in_days,
                metadata=metadata,
            )

            return {
                'success': True,
                'token': raw_token,  # Only returned once!
                'token_id': token_obj.token_id,
                'name': token_obj.name,
                'capabilities': [c.name for c in token_obj.capabilities],
                'expires_at': token_obj.expires_at.isoformat() if token_obj.expires_at else None,
                'warning': 'Store this token securely - it cannot be retrieved again!',
            }
        except (ValueError, TypeError, KeyError) as e:
            # Invalid parameters or token creation errors
            log_auth_error(e, "create_token", token_name=name)
            return {'success': False, 'error': str(e)}

    def _handle_create_tui_token(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a limited TUI dashboard token (no auth required).

        This allows the TUI to auto-authenticate on first connection.
        The token has read-only capabilities and is saved for future use.

        Params:
            name: str (optional) - Token name (default: tui-dashboard)
            client: str (optional) - Client identifier
        """
        try:
            name = params.get('name', 'tui-dashboard')
            client = params.get('client', 'unknown')

            # Check if a TUI token already exists
            existing_tokens = self.token_manager.list_tokens()
            for tok in existing_tokens:
                if tok.get('name', '').startswith('tui-'):
                    # Return error - TUI token already exists
                    # This prevents unlimited token creation
                    return {
                        'success': False,
                        'error': 'TUI token already exists. Use existing token or revoke it first.',
                        'existing_token_id': tok.get('token_id'),
                    }

            # Create a token for TUI with operator capabilities
            # Allows operators to view status and change modes
            # Does NOT allow token management (admin operations)
            tui_capabilities = {'operator'}  # Predefined operator capability set

            raw_token, token_obj = self.token_manager.create_token(
                name=f"tui-{name}",
                capabilities=tui_capabilities,
                created_by=f'tui-auto:{client}',
                expires_in_days=30,  # Short expiry for security
                metadata={'auto_created': True, 'client': client},
            )

            logger.info(f"Auto-created TUI token for client: {client}")

            return {
                'success': True,
                'token': raw_token,
                'token_id': token_obj.token_id,
                'name': token_obj.name,
                'capabilities': [c.name if hasattr(c, 'name') else str(c) for c in token_obj.capabilities],
                'expires_at': token_obj.expires_at.isoformat() if token_obj.expires_at else None,
                'message': 'TUI token created. Save this token - it will be used for future connections.',
            }
        except Exception as e:
            logger.error(f"Failed to create TUI token: {e}")
            return {'success': False, 'error': str(e)}

    def _handle_revoke_token(self, params: Dict[str, Any], requesting_token) -> Dict[str, Any]:
        """
        Revoke an API token.

        Params:
            token_id: str - Token ID to revoke (first 8 chars)
        """
        try:
            token_id = params.get('token_id')
            if not token_id:
                return {'success': False, 'error': 'token_id parameter required'}

            # Prevent self-revocation
            if requesting_token and requesting_token.token_id == token_id:
                return {'success': False, 'error': 'Cannot revoke your own token'}

            success, message = self.token_manager.revoke_token(
                token_id=token_id,
                revoked_by=requesting_token.name if requesting_token else 'system',
            )

            return {'success': success, 'message': message}
        except (ValueError, KeyError, IOError, OSError) as e:
            # Token lookup or persistence errors
            log_auth_error(e, "revoke_token", token_id=token_id)
            return {'success': False, 'error': str(e)}

    def _handle_list_tokens(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        List all API tokens.

        Params:
            include_revoked: bool (optional) - Include revoked tokens (default: False)
        """
        try:
            include_revoked = params.get('include_revoked', False)
            tokens = self.token_manager.list_tokens(include_revoked=include_revoked)

            return {
                'success': True,
                'tokens': tokens,
                'count': len(tokens),
            }
        except (IOError, OSError, json.JSONDecodeError) as e:
            # Token file access or parsing errors
            log_auth_error(e, "list_tokens")
            return {'success': False, 'error': str(e)}

    def _handle_rate_limit_status(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get rate limit status.

        Params:
            token_id: str (optional) - Get status for specific token
            include_all: bool (optional) - Include all tokens' rate limits (default: False)
        """
        try:
            token_id = params.get('token_id')
            include_all = params.get('include_all', False)

            if include_all:
                # Get global + all token rate limits
                all_status = self.token_manager.get_all_rate_limit_status()
                return {
                    'success': True,
                    'rate_limits': all_status,
                }
            elif token_id:
                # Get specific token's rate limit
                token_status = self.token_manager.get_rate_limit_status(token_id)
                return {
                    'success': True,
                    'token_id': token_id,
                    'rate_limit': token_status,
                }
            else:
                # Get just global rate limit
                global_status = self.token_manager.get_global_rate_limit_status()
                return {
                    'success': True,
                    'global_rate_limit': global_status,
                }
        except (KeyError, ValueError) as e:
            # Rate limit lookup errors
            return {'success': False, 'error': str(e)}

    def _handle_status(self) -> Dict[str, Any]:
        """Get daemon status"""
        try:
            status = self.daemon.get_status()
            return {'success': True, 'status': status}
        except (AttributeError, RuntimeError) as e:
            # Daemon not initialized or status unavailable
            return {'success': False, 'error': str(e)}

    def _handle_check_recall(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check if memory recall is permitted.

        Params:
            memory_class: int (0-5)
        """
        try:
            memory_class_value = params.get('memory_class')
            if memory_class_value is None:
                return {'success': False, 'error': 'memory_class parameter required'}

            memory_class = MemoryClass(memory_class_value)
            permitted, reason = self.daemon.check_recall_permission(memory_class)

            return {
                'success': True,
                'permitted': permitted,
                'reason': reason,
                'memory_class': memory_class_value
            }
        except ValueError as e:
            # Invalid memory class value
            return {'success': False, 'error': f'Invalid memory_class: {e}'}
        except (AttributeError, RuntimeError) as e:
            # Daemon/policy engine not available
            log_security_error(e, "check_recall", memory_class=memory_class_value)
            return {'success': False, 'error': str(e)}

    def _handle_check_tool(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check if tool execution is permitted.

        Params:
            tool_name: str
            requires_network: bool (optional)
            requires_filesystem: bool (optional)
            requires_usb: bool (optional)
        """
        try:
            tool_name = params.get('tool_name')
            if not tool_name:
                return {'success': False, 'error': 'tool_name parameter required'}

            requires_network = params.get('requires_network', False)
            requires_filesystem = params.get('requires_filesystem', False)
            requires_usb = params.get('requires_usb', False)

            permitted, reason = self.daemon.check_tool_permission(
                tool_name,
                requires_network=requires_network,
                requires_filesystem=requires_filesystem,
                requires_usb=requires_usb
            )

            return {
                'success': True,
                'permitted': permitted,
                'reason': reason,
                'tool_name': tool_name
            }
        except (AttributeError, RuntimeError) as e:
            # Daemon/policy engine not available
            log_security_error(e, "check_tool", tool_name=tool_name)
            return {'success': False, 'error': str(e)}

    def _handle_set_mode(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Request mode change.

        Params:
            mode: str (open|restricted|trusted|airgap|coldroom)
            operator: str (human|system)
            reason: str (optional)
        """
        try:
            mode_str = params.get('mode')
            operator_str = params.get('operator', 'human')
            reason = params.get('reason', '')

            if not mode_str:
                return {'success': False, 'error': 'mode parameter required'}

            # Parse mode
            mode_map = {
                'open': BoundaryMode.OPEN,
                'restricted': BoundaryMode.RESTRICTED,
                'trusted': BoundaryMode.TRUSTED,
                'airgap': BoundaryMode.AIRGAP,
                'coldroom': BoundaryMode.COLDROOM,
                'lockdown': BoundaryMode.LOCKDOWN
            }

            if mode_str.lower() not in mode_map:
                return {'success': False, 'error': f'Invalid mode: {mode_str}'}

            new_mode = mode_map[mode_str.lower()]

            # Parse operator
            operator = Operator.HUMAN if operator_str.lower() == 'human' else Operator.SYSTEM

            # Request transition
            success, message = self.daemon.request_mode_change(new_mode, operator, reason)

            return {
                'success': success,
                'message': message,
                'new_mode': mode_str
            }
        except ValueError as e:
            # Invalid mode or operator value
            return {'success': False, 'error': f'Invalid parameter: {e}'}
        except (AttributeError, RuntimeError) as e:
            # Daemon not available or mode change failed
            log_security_error(e, "set_mode", requested_mode=mode_str)
            return {'success': False, 'error': str(e)}

    def _handle_get_events(self, params: Dict[str, Any], client_info: str = None) -> Dict[str, Any]:
        """
        Get recent events.

        Params:
            count: int (optional, default 100)
            event_type: str (optional)
        """
        try:
            count = params.get('count', 100)
            event_type_str = params.get('event_type')

            if event_type_str:
                # Get events by type
                from daemon.event_logger import EventType
                event_type = EventType(event_type_str)
                events = self.daemon.event_logger.get_events_by_type(event_type, limit=count)
            else:
                # Get recent events
                events = self.daemon.event_logger.get_recent_events(count=count)

            # Convert events to dicts
            events_data = [event.to_dict() for event in events]

            # Track ingestion stats for SIEM panel
            self._track_ingestion(len(events_data), client_info)

            return {
                'success': True,
                'events': events_data,
                'count': len(events_data)
            }
        except ValueError as e:
            # Invalid event type value
            return {'success': False, 'error': f'Invalid event_type: {e}'}
        except (AttributeError, IOError, OSError) as e:
            # Event logger not available or file access error
            return {'success': False, 'error': str(e)}

    def _track_ingestion(self, event_count: int, client_info: str = None):
        """Track event ingestion statistics for SIEM clients."""
        import time
        from datetime import datetime, date
        with self._ingestion_lock:
            today = date.today().isoformat()

            # Reset daily counters if new day
            if self._ingestion_stats['today_date'] != today:
                self._ingestion_stats['today_date'] = today
                self._ingestion_stats['requests_today'] = 0
                self._ingestion_stats['events_today'] = 0

            # Track connection state - SIEM just connected/reconnected
            was_disconnected = not self._ingestion_stats['connected']
            self._ingestion_stats['connected'] = True
            self._ingestion_stats['was_connected'] = True

            # Log reconnection event if SIEM was previously disconnected
            if was_disconnected and self._ingestion_stats['total_requests'] > 0:
                self._log_siem_connection_event('connected', client_info)

            # Update stats
            self._ingestion_stats['total_requests'] += 1
            self._ingestion_stats['total_events_served'] += event_count
            self._ingestion_stats['requests_today'] += 1
            self._ingestion_stats['events_today'] += event_count
            self._ingestion_stats['last_request_time'] = datetime.utcnow().isoformat() + 'Z'
            self._ingestion_stats['last_request_timestamp'] = time.time()
            if client_info:
                self._ingestion_stats['last_client'] = client_info

    def _check_siem_connection_timeout(self):
        """Check if SIEM client has timed out and log disconnect event."""
        import time
        with self._ingestion_lock:
            if not self._ingestion_stats['connected']:
                return False  # Already disconnected

            last_ts = self._ingestion_stats['last_request_timestamp']
            if last_ts is None:
                return False  # Never connected

            elapsed = time.time() - last_ts
            if elapsed > self._ingestion_timeout:
                # SIEM has timed out - mark as disconnected
                self._ingestion_stats['connected'] = False
                self._log_siem_connection_event('disconnected', self._ingestion_stats['last_client'])
                return True
        return False

    def _log_siem_connection_event(self, state: str, client_info: str = None):
        """Log SIEM connection state change event."""
        if self.daemon and hasattr(self.daemon, 'event_logger'):
            try:
                client_str = f" (client: {client_info})" if client_info else ""
                if state == 'disconnected':
                    self.daemon.event_logger.log_event(
                        event_type='siem_disconnected',
                        severity='warning',
                        description=f'SIEM ingestion client disconnected{client_str} - no requests for {int(self._ingestion_timeout)}s',
                        data={'client': client_info, 'timeout': self._ingestion_timeout}
                    )
                else:
                    self.daemon.event_logger.log_event(
                        event_type='siem_connected',
                        severity='info',
                        description=f'SIEM ingestion client connected{client_str}',
                        data={'client': client_info}
                    )
            except Exception:
                pass  # Don't fail on logging errors

    def _handle_verify_log(self) -> Dict[str, Any]:
        """Verify event log integrity"""
        try:
            is_valid, error = self.daemon.event_logger.verify_chain()
            return {
                'success': True,
                'valid': is_valid,
                'error': error
            }
        except (AttributeError, IOError, OSError, json.JSONDecodeError) as e:
            # Event logger not available or log file access/parsing error
            log_security_error(e, "verify_log")
            return {'success': False, 'error': str(e)}

    def _handle_check_message(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check message content for policy compliance.

        Params:
            content: str - Message content to check
            source: str - Source system ('natlangchain', 'agent_os', or 'unknown')
            context: dict (optional) - Additional context
        """
        try:
            content = params.get('content')
            if content is None:
                return {'success': False, 'error': 'content parameter required'}

            source = params.get('source', 'unknown')
            context = params.get('context')

            # Check if message checker is available
            if not hasattr(self.daemon, 'check_message'):
                return {'success': False, 'error': 'Message checking not available'}

            permitted, reason, result = self.daemon.check_message(content, source, context)

            return {
                'success': True,
                'permitted': permitted,
                'reason': reason,
                'source': source,
                'result': result
            }
        except (AttributeError, RuntimeError) as e:
            # Message checker not available
            log_security_error(e, "check_message", source=source)
            return {'success': False, 'error': str(e)}

    def _handle_check_natlangchain(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check a NatLangChain blockchain entry.

        Params:
            author: str - Entry author
            intent: str - Intent description (prose)
            timestamp: str - Entry timestamp (ISO format)
            signature: str (optional) - Cryptographic signature
            previous_hash: str (optional) - Hash of previous entry
            metadata: dict (optional) - Additional metadata
        """
        try:
            author = params.get('author')
            intent = params.get('intent')
            timestamp = params.get('timestamp')

            if not author:
                return {'success': False, 'error': 'author parameter required'}
            if not intent:
                return {'success': False, 'error': 'intent parameter required'}
            if not timestamp:
                return {'success': False, 'error': 'timestamp parameter required'}

            signature = params.get('signature')
            previous_hash = params.get('previous_hash')
            metadata = params.get('metadata')

            # Check if message checker is available
            if not hasattr(self.daemon, 'check_natlangchain_entry'):
                return {'success': False, 'error': 'NatLangChain checking not available'}

            permitted, reason, result = self.daemon.check_natlangchain_entry(
                author=author,
                intent=intent,
                timestamp=timestamp,
                signature=signature,
                previous_hash=previous_hash,
                metadata=metadata
            )

            return {
                'success': True,
                'permitted': permitted,
                'reason': reason,
                'author': author,
                'result': result
            }
        except (AttributeError, RuntimeError) as e:
            # NatLangChain checker not available
            log_security_error(e, "check_natlangchain", author=author)
            return {'success': False, 'error': str(e)}

    def _handle_check_agentos(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check an Agent-OS inter-agent message.

        Params:
            sender_agent: str - Sending agent identifier
            recipient_agent: str - Receiving agent identifier
            content: str - Message content
            message_type: str - Type of message (request, response, notification, command)
            authority_level: int - Authority level (0-5)
            timestamp: str (optional) - Message timestamp (ISO format)
            requires_consent: bool (optional) - Whether consent is required
            metadata: dict (optional) - Additional metadata
        """
        try:
            sender_agent = params.get('sender_agent')
            recipient_agent = params.get('recipient_agent')
            content = params.get('content')

            if not sender_agent:
                return {'success': False, 'error': 'sender_agent parameter required'}
            if not recipient_agent:
                return {'success': False, 'error': 'recipient_agent parameter required'}
            if not content:
                return {'success': False, 'error': 'content parameter required'}

            message_type = params.get('message_type', 'request')
            authority_level = params.get('authority_level', 0)
            timestamp = params.get('timestamp')
            requires_consent = params.get('requires_consent', False)
            metadata = params.get('metadata')

            # Check if message checker is available
            if not hasattr(self.daemon, 'check_agentos_message'):
                return {'success': False, 'error': 'Agent-OS checking not available'}

            permitted, reason, result = self.daemon.check_agentos_message(
                sender_agent=sender_agent,
                recipient_agent=recipient_agent,
                content=content,
                message_type=message_type,
                authority_level=authority_level,
                timestamp=timestamp,
                requires_consent=requires_consent,
                metadata=metadata
            )

            return {
                'success': True,
                'permitted': permitted,
                'reason': reason,
                'sender_agent': sender_agent,
                'recipient_agent': recipient_agent,
                'result': result
            }
        except (AttributeError, RuntimeError) as e:
            # Agent-OS checker not available
            log_security_error(e, "check_agentos", sender=sender_agent, recipient=recipient_agent)
            return {'success': False, 'error': str(e)}

    # === Monitoring API Handlers (Plan 11) ===

    def _handle_get_memory_stats(self) -> Dict[str, Any]:
        """
        Get memory monitoring statistics.

        Returns memory usage, leak detection status, and growth trends.
        """
        try:
            if not hasattr(self.daemon, 'memory_monitor') or not self.daemon.memory_monitor:
                return {'success': False, 'error': 'Memory monitor not available'}

            if not getattr(self.daemon, 'memory_monitor_enabled', False):
                return {'success': False, 'error': 'Memory monitor not enabled'}

            stats = self.daemon.memory_monitor.get_stats()
            return {
                'success': True,
                'memory_stats': stats,
            }
        except (AttributeError, RuntimeError) as e:
            # Memory monitor not available or failed to get stats
            return {'success': False, 'error': str(e)}

    def _handle_toggle_memory_debug(self) -> Dict[str, Any]:
        """
        Toggle memory debug mode (tracemalloc) for leak detection.

        When enabled, tracks allocation sites to help identify memory leak sources.
        Returns the new debug mode state.
        """
        try:
            if not hasattr(self.daemon, 'memory_monitor') or not self.daemon.memory_monitor:
                return {'success': False, 'error': 'Memory monitor not available'}

            if not getattr(self.daemon, 'memory_monitor_enabled', False):
                return {'success': False, 'error': 'Memory monitor not enabled'}

            # Toggle debug mode
            monitor = self.daemon.memory_monitor
            if hasattr(monitor, '_debugger') and monitor._debugger:
                if monitor._debugger.is_enabled:
                    monitor.disable_debug_mode()
                    debug_enabled = False
                else:
                    monitor.enable_debug_mode()
                    debug_enabled = True
            else:
                # Try to enable debug mode
                monitor.enable_debug_mode()
                debug_enabled = True

            return {
                'success': True,
                'debug_enabled': debug_enabled,
                'message': f"Memory debug mode {'enabled' if debug_enabled else 'disabled'}"
            }
        except (AttributeError, RuntimeError) as e:
            return {'success': False, 'error': str(e)}

    def _handle_get_resource_stats(self) -> Dict[str, Any]:
        """
        Get resource monitoring statistics.

        Returns CPU, file descriptor, thread, disk, and connection stats.
        """
        try:
            if not hasattr(self.daemon, 'resource_monitor') or not self.daemon.resource_monitor:
                return {'success': False, 'error': 'Resource monitor not available'}

            if not getattr(self.daemon, 'resource_monitor_enabled', False):
                return {'success': False, 'error': 'Resource monitor not enabled'}

            result = {
                'success': True,
                'sample_count': self.daemon.resource_monitor._sample_count,
            }

            # Get CPU stats if available
            if hasattr(self.daemon.resource_monitor, 'get_cpu_stats'):
                result['cpu_stats'] = self.daemon.resource_monitor.get_cpu_stats()

            # Get connection stats if available
            if hasattr(self.daemon.resource_monitor, 'get_connection_stats'):
                result['connection_stats'] = self.daemon.resource_monitor.get_connection_stats()

            # Get current snapshot
            if hasattr(self.daemon.resource_monitor, 'get_current_snapshot'):
                snapshot = self.daemon.resource_monitor.get_current_snapshot()
                if snapshot:
                    result['current_snapshot'] = {
                        'timestamp': snapshot.timestamp,
                        'fd_count': snapshot.fd_count,
                        'thread_count': snapshot.thread_count,
                        'disk_used_percent': snapshot.disk_used_percent,
                        'cpu_percent': snapshot.cpu_percent,
                        'connection_count': snapshot.connection_count,
                    }

            return result
        except (AttributeError, RuntimeError) as e:
            # Resource monitor not available or failed to get stats
            return {'success': False, 'error': str(e)}

    def _handle_get_health_stats(self) -> Dict[str, Any]:
        """
        Get health monitoring statistics.

        Returns overall health status, component health, and heartbeat info.
        """
        try:
            if not hasattr(self.daemon, 'health_monitor') or not self.daemon.health_monitor:
                return {'success': False, 'error': 'Health monitor not available'}

            if not getattr(self.daemon, 'health_monitor_enabled', False):
                return {'success': False, 'error': 'Health monitor not enabled'}

            summary = self.daemon.health_monitor.get_summary()
            return {
                'success': True,
                'health_stats': summary,
            }
        except (AttributeError, RuntimeError) as e:
            # Health monitor not available or failed to get stats
            return {'success': False, 'error': str(e)}

    def _handle_get_queue_stats(self) -> Dict[str, Any]:
        """
        Get queue monitoring statistics.

        Returns queue depths, backpressure state, and latency info.
        """
        try:
            if not hasattr(self.daemon, 'queue_monitor') or not self.daemon.queue_monitor:
                return {'success': False, 'error': 'Queue monitor not available'}

            if not getattr(self.daemon, 'queue_monitor_enabled', False):
                return {'success': False, 'error': 'Queue monitor not enabled'}

            summary = self.daemon.queue_monitor.get_summary()
            return {
                'success': True,
                'queue_stats': summary,
            }
        except (AttributeError, RuntimeError) as e:
            # Queue monitor not available or failed to get stats
            return {'success': False, 'error': str(e)}

    def _handle_get_monitoring_summary(self) -> Dict[str, Any]:
        """
        Get a combined summary of all monitoring systems.

        Returns memory, resource, health, and queue stats in one response.
        """
        try:
            result = {
                'success': True,
                'monitors': {},
            }

            # Memory monitor
            if hasattr(self.daemon, 'memory_monitor') and self.daemon.memory_monitor:
                if getattr(self.daemon, 'memory_monitor_enabled', False):
                    try:
                        result['monitors']['memory'] = {
                            'enabled': True,
                            'stats': self.daemon.memory_monitor.get_stats(),
                        }
                    except (AttributeError, RuntimeError) as e:
                        result['monitors']['memory'] = {'enabled': True, 'error': str(e)}
                else:
                    result['monitors']['memory'] = {'enabled': False}
            else:
                result['monitors']['memory'] = {'available': False}

            # Resource monitor
            if hasattr(self.daemon, 'resource_monitor') and self.daemon.resource_monitor:
                if getattr(self.daemon, 'resource_monitor_enabled', False):
                    try:
                        resource_data = {'enabled': True}
                        if hasattr(self.daemon.resource_monitor, 'get_cpu_stats'):
                            resource_data['cpu'] = self.daemon.resource_monitor.get_cpu_stats()
                        if hasattr(self.daemon.resource_monitor, 'get_connection_stats'):
                            resource_data['connections'] = self.daemon.resource_monitor.get_connection_stats()
                        result['monitors']['resource'] = resource_data
                    except (AttributeError, RuntimeError) as e:
                        result['monitors']['resource'] = {'enabled': True, 'error': str(e)}
                else:
                    result['monitors']['resource'] = {'enabled': False}
            else:
                result['monitors']['resource'] = {'available': False}

            # Health monitor
            if hasattr(self.daemon, 'health_monitor') and self.daemon.health_monitor:
                if getattr(self.daemon, 'health_monitor_enabled', False):
                    try:
                        result['monitors']['health'] = {
                            'enabled': True,
                            'stats': self.daemon.health_monitor.get_summary(),
                        }
                    except (AttributeError, RuntimeError) as e:
                        result['monitors']['health'] = {'enabled': True, 'error': str(e)}
                else:
                    result['monitors']['health'] = {'enabled': False}
            else:
                result['monitors']['health'] = {'available': False}

            # Queue monitor
            if hasattr(self.daemon, 'queue_monitor') and self.daemon.queue_monitor:
                if getattr(self.daemon, 'queue_monitor_enabled', False):
                    try:
                        result['monitors']['queue'] = {
                            'enabled': True,
                            'stats': self.daemon.queue_monitor.get_summary(),
                        }
                    except (AttributeError, RuntimeError) as e:
                        result['monitors']['queue'] = {'enabled': True, 'error': str(e)}
                else:
                    result['monitors']['queue'] = {'enabled': False}
            else:
                result['monitors']['queue'] = {'available': False}

            return result
        except (AttributeError, RuntimeError) as e:
            # Daemon or monitors not available
            return {'success': False, 'error': str(e)}

    # === Report Generation Handlers (Plan 11) ===

    def _handle_generate_report(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a monitoring report with Ollama interpretation.

        Params:
            report_type: str (optional) - 'full', 'summary', 'alerts', 'health' (default: 'full')
            interpret: bool (optional) - Whether to send to Ollama (default: True)
            custom_prompt: str (optional) - Custom prompt for Ollama
            ollama_model: str (optional) - Override Ollama model
            ollama_endpoint: str (optional) - Override Ollama endpoint
        """
        try:
            if not hasattr(self.daemon, 'report_generator') or not self.daemon.report_generator:
                return {'success': False, 'error': 'Report generator not available'}

            # Import ReportType
            from daemon.monitoring_report import ReportType, OllamaConfig

            # Parse report type
            report_type_str = params.get('report_type', 'full')
            report_type_map = {
                'full': ReportType.FULL,
                'summary': ReportType.SUMMARY,
                'alerts': ReportType.ALERTS,
                'health': ReportType.HEALTH,
            }
            report_type = report_type_map.get(report_type_str, ReportType.FULL)

            # Check for Ollama config overrides
            if params.get('ollama_model') or params.get('ollama_endpoint'):
                config = OllamaConfig(
                    endpoint=params.get('ollama_endpoint', 'http://localhost:11434'),
                    model=params.get('ollama_model', 'llama3.2'),
                )
                self.daemon.report_generator.set_ollama_config(config)

            # Generate report
            interpret = params.get('interpret', True)
            custom_prompt = params.get('custom_prompt')

            report = self.daemon.report_generator.generate_report(
                report_type=report_type,
                interpret=interpret,
                custom_prompt=custom_prompt,
            )

            return {
                'success': True,
                'report': report.to_dict(),
            }
        except ImportError as e:
            # Report module not available
            return {'success': False, 'error': f'Report module not available: {e}'}
        except (AttributeError, RuntimeError, ConnectionError, TimeoutError) as e:
            # Report generator not available or Ollama connection failed
            return {'success': False, 'error': str(e)}

    def _handle_get_raw_report(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a raw monitoring report without Ollama interpretation.

        Params:
            report_type: str (optional) - 'full', 'summary', 'alerts', 'health' (default: 'full')
        """
        try:
            if not hasattr(self.daemon, 'report_generator') or not self.daemon.report_generator:
                return {'success': False, 'error': 'Report generator not available'}

            from daemon.monitoring_report import ReportType

            report_type_str = params.get('report_type', 'full')
            report_type_map = {
                'full': ReportType.FULL,
                'summary': ReportType.SUMMARY,
                'alerts': ReportType.ALERTS,
                'health': ReportType.HEALTH,
            }
            report_type = report_type_map.get(report_type_str, ReportType.FULL)

            raw_data = self.daemon.report_generator.generate_raw_report(report_type)

            return {
                'success': True,
                'raw_report': raw_data,
            }
        except ImportError as e:
            # Report module not available
            return {'success': False, 'error': f'Report module not available: {e}'}
        except (AttributeError, RuntimeError) as e:
            # Report generator not available
            return {'success': False, 'error': str(e)}

    def _handle_check_ollama_status(self) -> Dict[str, Any]:
        """
        Check Ollama availability and list available models.
        """
        try:
            if not hasattr(self.daemon, 'report_generator') or not self.daemon.report_generator:
                return {'success': False, 'error': 'Report generator not available'}

            status = self.daemon.report_generator.check_ollama_status()

            return {
                'success': True,
                'ollama_status': status,
            }
        except (AttributeError, RuntimeError, ConnectionError, TimeoutError) as e:
            # Report generator not available or Ollama connection failed
            return {'success': False, 'error': str(e)}

    def _handle_get_report_history(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get recent report generation history.

        Params:
            limit: int (optional) - Number of reports to return (default: 10)
        """
        try:
            if not hasattr(self.daemon, 'report_generator') or not self.daemon.report_generator:
                return {'success': False, 'error': 'Report generator not available'}

            limit = params.get('limit', 10)
            history = self.daemon.report_generator.get_report_history(limit=limit)

            return {
                'success': True,
                'history': history,
                'count': len(history),
            }
        except (AttributeError, RuntimeError) as e:
            # Report generator not available
            return {'success': False, 'error': str(e)}

    def _handle_query(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Query the daemon using natural language via Ollama.

        Params:
            question: str - Natural language question about the daemon
            include_history: bool (optional) - Include recent events in context
        """
        try:
            if not hasattr(self.daemon, 'report_generator') or not self.daemon.report_generator:
                return {'success': False, 'error': 'Report generator not available'}

            question = params.get('question')
            if not question:
                return {'success': False, 'error': 'question parameter required'}

            include_history = params.get('include_history', False)

            result = self.daemon.report_generator.query(
                question=question,
                include_history=include_history,
            )

            return result

        except (AttributeError, RuntimeError, ConnectionError, TimeoutError) as e:
            # Report generator not available or Ollama connection failed
            return {'success': False, 'error': str(e)}

    def _handle_get_alerts(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get active alerts from daemon monitors.

        Params:
            limit: int (optional) - Maximum number of alerts to return
        """
        try:
            alerts = []
            limit = params.get('limit', 50)

            # Collect alerts from various monitors if available
            if hasattr(self.daemon, 'health_monitor') and self.daemon.health_monitor:
                try:
                    health_alerts = self.daemon.health_monitor.get_alerts(limit=limit)
                    for alert in health_alerts:
                        alerts.append({
                            'alert_id': getattr(alert, 'alert_id', str(id(alert))),
                            'timestamp': getattr(alert, 'timestamp', datetime.now()).isoformat() if hasattr(alert, 'timestamp') else datetime.now().isoformat(),
                            'severity': getattr(alert, 'severity', 'MEDIUM'),
                            'message': getattr(alert, 'message', str(alert)),
                            'status': getattr(alert, 'status', 'NEW'),
                            'source': 'health_monitor',
                        })
                except Exception:
                    pass

            if hasattr(self.daemon, 'resource_monitor') and self.daemon.resource_monitor:
                try:
                    resource_alerts = self.daemon.resource_monitor.get_alerts(limit=limit)
                    for alert in resource_alerts:
                        alerts.append({
                            'alert_id': getattr(alert, 'alert_id', str(id(alert))),
                            'timestamp': getattr(alert, 'timestamp', datetime.now()).isoformat() if hasattr(alert, 'timestamp') else datetime.now().isoformat(),
                            'severity': getattr(alert, 'severity', 'MEDIUM'),
                            'message': getattr(alert, 'message', str(alert)),
                            'status': getattr(alert, 'status', 'NEW'),
                            'source': 'resource_monitor',
                        })
                except Exception:
                    pass

            # Sort by timestamp descending and limit
            alerts.sort(key=lambda x: x['timestamp'], reverse=True)
            alerts = alerts[:limit]

            return {'success': True, 'alerts': alerts}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _handle_get_sandboxes(self) -> Dict[str, Any]:
        """Get active sandbox status."""
        try:
            sandboxes = []

            # Check if sandbox manager is available
            if hasattr(self.daemon, 'sandbox_manager') and self.daemon.sandbox_manager:
                try:
                    for sandbox_id, sandbox in self.daemon.sandbox_manager.sandboxes.items():
                        sandboxes.append({
                            'sandbox_id': sandbox_id,
                            'profile': getattr(sandbox, 'profile', 'standard'),
                            'status': getattr(sandbox, 'status', 'unknown'),
                            'memory_used': getattr(sandbox, 'memory_used', 0),
                            'memory_limit': getattr(sandbox, 'memory_limit', 0),
                            'cpu_percent': getattr(sandbox, 'cpu_percent', 0.0),
                            'uptime': getattr(sandbox, 'uptime', 0.0),
                        })
                except Exception:
                    pass

            return {'success': True, 'sandboxes': sandboxes}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _handle_get_siem_status(self) -> Dict[str, Any]:
        """Get SIEM integration status including ingestion stats."""
        try:
            # Check for SIEM connection timeout (logs warning if disconnected)
            self._check_siem_connection_timeout()

            # Get ingestion stats (events pulled by SIEM clients)
            with self._ingestion_lock:
                ingestion_connected = self._ingestion_stats['connected']
                ingestion_was_connected = self._ingestion_stats['was_connected']
                ingestion = {
                    'active': self._ingestion_stats['requests_today'] > 0,
                    'connected': ingestion_connected,
                    'was_connected': ingestion_was_connected,  # True if ever connected
                    'requests_today': self._ingestion_stats['requests_today'],
                    'events_served_today': self._ingestion_stats['events_today'],
                    'last_request': self._ingestion_stats['last_request_time'],
                    'last_client': self._ingestion_stats['last_client'],
                    'total_requests': self._ingestion_stats['total_requests'],
                    'total_events_served': self._ingestion_stats['total_events_served'],
                }

            # Try to get SIEM integration status (outbound shipping)
            try:
                from daemon.security.siem_integration import get_siem
                siem = get_siem()
                if siem and siem.connector:
                    stats = siem.connector.get_stats()
                    return {
                        'success': True,
                        'siem_status': {
                            'connected': stats.get('connected', False),
                            'backend': siem.config.transport.value if hasattr(siem.config, 'transport') else 'unknown',
                            'queue_depth': stats.get('buffer_size', 0),
                            'events_shipped_today': stats.get('events_sent', 0),
                            'last_ship_time': stats.get('last_send_time', ''),
                            'errors_today': stats.get('send_failures', 0),
                        },
                        'ingestion': ingestion,
                    }
            except ImportError:
                pass

            # Return disconnected status if SIEM shipping not available
            # But still show ingestion stats if SIEM clients are pulling events
            return {
                'success': True,
                'siem_status': {
                    'connected': False,
                    'backend': 'none',
                    'queue_depth': 0,
                    'events_shipped_today': 0,
                    'last_ship_time': '',
                    'errors_today': 0,
                },
                'ingestion': ingestion,
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}


class BoundaryAPIClient:
    """
    Client for communicating with the Boundary Daemon API.
    Used by other Agent OS components (Memory Vault, synth-mind, etc.)

    Authentication:
        The client requires an API token for authentication. Tokens can be:
        1. Passed directly to the constructor
        2. Loaded from BOUNDARY_API_TOKEN environment variable
        3. Loaded from a token file

    Example:
        # Using environment variable
        os.environ['BOUNDARY_API_TOKEN'] = 'bd_...'
        client = BoundaryAPIClient()

        # Using direct token
        client = BoundaryAPIClient(token='bd_...')

        # Using token file
        client = BoundaryAPIClient(token_file='./my_token.txt')
    """

    def __init__(
        self,
        socket_path: str = './api/boundary.sock',
        token: Optional[str] = None,
        token_file: Optional[str] = None,
    ):
        """
        Initialize API client.

        Args:
            socket_path: Path to Unix socket
            token: API token for authentication (optional if using env var)
            token_file: Path to file containing API token
        """
        self.socket_path = socket_path
        self._token = self._resolve_token(token, token_file)

    def _resolve_token(
        self,
        token: Optional[str],
        token_file: Optional[str],
    ) -> Optional[str]:
        """Resolve token from various sources."""
        # Priority: direct token > token file > environment variable
        if token:
            return token.strip()

        if token_file:
            try:
                with open(token_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            return line
            except (IOError, OSError, PermissionError) as e:
                # Token file access errors
                logger.warning(f"Could not read token file: {e}")

        # Try environment variable
        env_token = os.environ.get('BOUNDARY_API_TOKEN')
        if env_token:
            return env_token.strip()

        return None

    @property
    def token(self) -> Optional[str]:
        """Get the current token (masked for security)."""
        if self._token:
            return f"{self._token[:12]}...{self._token[-4:]}"
        return None

    def set_token(self, token: str):
        """Set the API token."""
        self._token = token.strip()

    def _send_request(self, command: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Send an authenticated request to the daemon."""
        request = {
            'command': command,
            'params': params or {},
        }

        # Add token if available
        if self._token:
            request['token'] = self._token

        try:
            # Connect to socket
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(self.socket_path)

            # Send request
            sock.sendall(json.dumps(request).encode('utf-8'))

            # Receive response
            data = sock.recv(4096)
            response = json.loads(data.decode('utf-8'))

            sock.close()
            return response

        except FileNotFoundError:
            return {
                'success': False,
                'error': f'Daemon not running - socket not found at {self.socket_path}\n'
                         f'Start the daemon with: python -m daemon.boundary_daemon'
            }
        except ConnectionRefusedError:
            return {
                'success': False,
                'error': f'Daemon not responding - connection refused at {self.socket_path}\n'
                         f'The daemon may have crashed. Check logs and restart.'
            }
        except PermissionError:
            return {
                'success': False,
                'error': f'Permission denied - cannot access socket at {self.socket_path}\n'
                         f'Check socket permissions or run with appropriate privileges.'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_status(self) -> Dict[str, Any]:
        """Get daemon status"""
        return self._send_request('status')

    def check_recall(self, memory_class: int) -> tuple[bool, str]:
        """
        Check if memory recall is permitted.

        Args:
            memory_class: Memory classification level (0-5)

        Returns:
            (permitted, reason)
        """
        response = self._send_request('check_recall', {'memory_class': memory_class})

        if not response.get('success'):
            return (False, response.get('error', 'Unknown error'))

        return (response.get('permitted', False), response.get('reason', ''))

    def check_tool(self, tool_name: str, requires_network: bool = False,
                   requires_filesystem: bool = False, requires_usb: bool = False) -> tuple[bool, str]:
        """
        Check if tool execution is permitted.

        Args:
            tool_name: Name of the tool
            requires_network: Tool needs network
            requires_filesystem: Tool needs filesystem
            requires_usb: Tool needs USB

        Returns:
            (permitted, reason)
        """
        params = {
            'tool_name': tool_name,
            'requires_network': requires_network,
            'requires_filesystem': requires_filesystem,
            'requires_usb': requires_usb
        }
        response = self._send_request('check_tool', params)

        if not response.get('success'):
            return (False, response.get('error', 'Unknown error'))

        return (response.get('permitted', False), response.get('reason', ''))

    def set_mode(self, mode: str, operator: str = 'human', reason: str = '') -> tuple[bool, str]:
        """
        Request mode change.

        Args:
            mode: Target mode (open|restricted|trusted|airgap|coldroom)
            operator: Who is requesting (human|system)
            reason: Reason for change

        Returns:
            (success, message)
        """
        params = {
            'mode': mode,
            'operator': operator,
            'reason': reason
        }
        response = self._send_request('set_mode', params)

        return (response.get('success', False), response.get('message', response.get('error', '')))

    def get_events(self, count: int = 100, event_type: Optional[str] = None) -> list:
        """
        Get recent events.

        Args:
            count: Number of events to retrieve
            event_type: Filter by event type (optional)

        Returns:
            List of events
        """
        params = {'count': count}
        if event_type:
            params['event_type'] = event_type

        response = self._send_request('get_events', params)

        if not response.get('success'):
            return []

        return response.get('events', [])

    def verify_log(self) -> tuple[bool, Optional[str]]:
        """
        Verify event log integrity.

        Returns:
            (is_valid, error_message)
        """
        response = self._send_request('verify_log')

        if not response.get('success'):
            return (False, response.get('error'))

        return (response.get('valid', False), response.get('error'))

    def check_message(self, content: str, source: str = 'unknown',
                      context: Optional[Dict[str, Any]] = None) -> tuple[bool, str, Optional[Dict]]:
        """
        Check message content for policy compliance.

        Args:
            content: Message content to check
            source: Source system ('natlangchain', 'agent_os', or 'unknown')
            context: Additional context (optional)

        Returns:
            (permitted, reason, result_data)
        """
        params = {
            'content': content,
            'source': source
        }
        if context:
            params['context'] = context

        response = self._send_request('check_message', params)

        if not response.get('success'):
            return (False, response.get('error', 'Unknown error'), None)

        return (
            response.get('permitted', False),
            response.get('reason', ''),
            response.get('result')
        )

    def check_natlangchain(self, author: str, intent: str, timestamp: str,
                           signature: Optional[str] = None,
                           previous_hash: Optional[str] = None,
                           metadata: Optional[Dict[str, Any]] = None) -> tuple[bool, str, Optional[Dict]]:
        """
        Check a NatLangChain blockchain entry.

        Args:
            author: Entry author
            intent: Intent description (prose)
            timestamp: Entry timestamp (ISO format)
            signature: Cryptographic signature (optional)
            previous_hash: Hash of previous entry (optional)
            metadata: Additional metadata (optional)

        Returns:
            (permitted, reason, result_data)
        """
        params = {
            'author': author,
            'intent': intent,
            'timestamp': timestamp
        }
        if signature:
            params['signature'] = signature
        if previous_hash:
            params['previous_hash'] = previous_hash
        if metadata:
            params['metadata'] = metadata

        response = self._send_request('check_natlangchain', params)

        if not response.get('success'):
            return (False, response.get('error', 'Unknown error'), None)

        return (
            response.get('permitted', False),
            response.get('reason', ''),
            response.get('result')
        )

    def check_agentos(self, sender_agent: str, recipient_agent: str, content: str,
                      message_type: str = 'request', authority_level: int = 0,
                      timestamp: Optional[str] = None, requires_consent: bool = False,
                      metadata: Optional[Dict[str, Any]] = None) -> tuple[bool, str, Optional[Dict]]:
        """
        Check an Agent-OS inter-agent message.

        Args:
            sender_agent: Sending agent identifier
            recipient_agent: Receiving agent identifier
            content: Message content
            message_type: Type of message (request, response, notification, command)
            authority_level: Authority level (0-5)
            timestamp: Message timestamp (optional, ISO format)
            requires_consent: Whether consent is required
            metadata: Additional metadata (optional)

        Returns:
            (permitted, reason, result_data)
        """
        params = {
            'sender_agent': sender_agent,
            'recipient_agent': recipient_agent,
            'content': content,
            'message_type': message_type,
            'authority_level': authority_level,
            'requires_consent': requires_consent
        }
        if timestamp:
            params['timestamp'] = timestamp
        if metadata:
            params['metadata'] = metadata

        response = self._send_request('check_agentos', params)

        if not response.get('success'):
            return (False, response.get('error', 'Unknown error'), None)

        return (
            response.get('permitted', False),
            response.get('reason', ''),
            response.get('result')
        )

    # Token management methods (require MANAGE_TOKENS capability)

    def create_token(
        self,
        name: str,
        capabilities: list,
        expires_in_days: Optional[int] = 365,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create a new API token.

        Args:
            name: Human-readable name for the token
            capabilities: List of capabilities or capability set name
                         Options: 'readonly', 'operator', 'admin'
                         Or individual: 'STATUS', 'READ_EVENTS', 'SET_MODE', etc.
            expires_in_days: Days until expiration (None = never)
            metadata: Additional metadata

        Returns:
            Response containing the new token (store securely!)
        """
        params = {
            'name': name,
            'capabilities': capabilities,
        }
        if expires_in_days is not None:
            params['expires_in_days'] = expires_in_days
        if metadata:
            params['metadata'] = metadata

        return self._send_request('create_token', params)

    def revoke_token(self, token_id: str) -> Dict[str, Any]:
        """
        Revoke an API token.

        Args:
            token_id: Token ID to revoke (first 8 characters)

        Returns:
            Response indicating success/failure
        """
        return self._send_request('revoke_token', {'token_id': token_id})

    def list_tokens(self, include_revoked: bool = False) -> Dict[str, Any]:
        """
        List all API tokens.

        Args:
            include_revoked: Whether to include revoked tokens

        Returns:
            Response containing list of tokens
        """
        return self._send_request('list_tokens', {'include_revoked': include_revoked})

    # Monitoring methods (Plan 11)

    def get_memory_stats(self) -> Dict[str, Any]:
        """
        Get memory monitoring statistics.

        Returns:
            Response containing memory usage, leak detection, and growth trends.
        """
        return self._send_request('get_memory_stats')

    def get_resource_stats(self) -> Dict[str, Any]:
        """
        Get resource monitoring statistics.

        Returns:
            Response containing CPU, FD, thread, disk, and connection stats.
        """
        return self._send_request('get_resource_stats')

    def get_health_stats(self) -> Dict[str, Any]:
        """
        Get health monitoring statistics.

        Returns:
            Response containing overall health, component status, and heartbeat info.
        """
        return self._send_request('get_health_stats')

    def get_queue_stats(self) -> Dict[str, Any]:
        """
        Get queue monitoring statistics.

        Returns:
            Response containing queue depths, backpressure, and latency info.
        """
        return self._send_request('get_queue_stats')

    def get_monitoring_summary(self) -> Dict[str, Any]:
        """
        Get a combined summary of all monitoring systems.

        Returns:
            Response containing memory, resource, health, and queue stats.
        """
        return self._send_request('get_monitoring_summary')

    # Report generation methods (Plan 11)

    def generate_report(
        self,
        report_type: str = 'full',
        interpret: bool = True,
        custom_prompt: Optional[str] = None,
        ollama_model: Optional[str] = None,
        ollama_endpoint: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Generate a monitoring report with Ollama interpretation.

        Args:
            report_type: Type of report - 'full', 'summary', 'alerts', 'health'
            interpret: Whether to send to Ollama for interpretation
            custom_prompt: Custom prompt for Ollama analysis
            ollama_model: Override the configured Ollama model
            ollama_endpoint: Override the configured Ollama endpoint

        Returns:
            Response containing the report with raw data and interpretation.
        """
        params = {'report_type': report_type, 'interpret': interpret}
        if custom_prompt:
            params['custom_prompt'] = custom_prompt
        if ollama_model:
            params['ollama_model'] = ollama_model
        if ollama_endpoint:
            params['ollama_endpoint'] = ollama_endpoint
        return self._send_request('generate_report', params)

    def get_raw_report(self, report_type: str = 'full') -> Dict[str, Any]:
        """
        Generate a raw monitoring report without Ollama interpretation.

        Args:
            report_type: Type of report - 'full', 'summary', 'alerts', 'health'

        Returns:
            Response containing raw monitoring data.
        """
        return self._send_request('get_raw_report', {'report_type': report_type})

    def check_ollama_status(self) -> Dict[str, Any]:
        """
        Check Ollama availability and list available models.

        Returns:
            Response containing Ollama status and available models.
        """
        return self._send_request('check_ollama_status')

    def get_report_history(self, limit: int = 10) -> Dict[str, Any]:
        """
        Get recent report generation history.

        Args:
            limit: Number of reports to return

        Returns:
            Response containing recent report history.
        """
        return self._send_request('get_report_history', {'limit': limit})

    def query(self, question: str, include_history: bool = False) -> Dict[str, Any]:
        """
        Query the daemon using natural language via Ollama.

        Args:
            question: Natural language question about the daemon
            include_history: Whether to include recent events in context

        Returns:
            Response containing the AI-generated answer.

        Examples:
            client.query("What is the current memory usage?")
            client.query("Are there any critical issues?")
            client.query("What security mode is the daemon in?")
        """
        return self._send_request('query', {
            'question': question,
            'include_history': include_history,
        })


if __name__ == '__main__':
    # Test client
    print("Testing Boundary API Client...")

    client = BoundaryAPIClient()

    # Test status
    print("\nGetting status...")
    status_response = client.get_status()
    print(f"Status: {status_response}")

    # Test recall check
    print("\nChecking recall permission for memory class 2...")
    permitted, reason = client.check_recall(memory_class=2)
    print(f"Permitted: {permitted}, Reason: {reason}")

    # Test tool check
    print("\nChecking tool permission...")
    permitted, reason = client.check_tool('test_tool', requires_network=True)
    print(f"Permitted: {permitted}, Reason: {reason}")

    # Test message check
    print("\nChecking message content...")
    permitted, reason, result = client.check_message(
        content="Test message content",
        source="natlangchain"
    )
    print(f"Permitted: {permitted}, Reason: {reason}")

    # Test NatLangChain entry check
    print("\nChecking NatLangChain entry...")
    from datetime import datetime
    permitted, reason, result = client.check_natlangchain(
        author="user@example.com",
        intent="I want to share my research with the team",
        timestamp=datetime.utcnow().isoformat() + "Z"
    )
    print(f"Permitted: {permitted}, Reason: {reason}")

    # Test Agent-OS message check
    print("\nChecking Agent-OS message...")
    permitted, reason, result = client.check_agentos(
        sender_agent="orchestrator",
        recipient_agent="executor",
        content="Process the approved request",
        message_type="request",
        authority_level=1
    )
    print(f"Permitted: {permitted}, Reason: {reason}")

    print("\nAPI client test complete.")
