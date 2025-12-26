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
import os
import socket
import threading
from typing import Optional, Dict, Any

from daemon.policy_engine import BoundaryMode, Operator, MemoryClass
from daemon.auth.api_auth import (
    TokenManager,
    AuthenticationMiddleware,
    APICapability,
    COMMAND_CAPABILITIES,
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
        """
        self.daemon = daemon
        self.socket_path = socket_path
        self.require_auth = require_auth
        self._running = False
        self._server_thread: Optional[threading.Thread] = None
        self._socket: Optional[socket.socket] = None

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

        # Remove stale socket
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

        # Remove socket file
        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)

    def _server_loop(self):
        """Main server loop"""
        try:
            # Create Unix socket
            self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._socket.bind(self.socket_path)
            self._socket.listen(5)

            # Set permissions (owner only)
            os.chmod(self.socket_path, 0o600)

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

                except Exception as e:
                    if self._running:
                        print(f"Error in server loop: {e}")

        except Exception as e:
            print(f"Fatal error in API server: {e}")
        finally:
            if self._socket:
                self._socket.close()

    def _handle_client(self, conn: socket.socket):
        """Handle a client connection"""
        try:
            # Read request (max 4KB)
            data = conn.recv(4096)
            if not data:
                return

            # Parse JSON request
            try:
                request = json.loads(data.decode('utf-8'))
            except json.JSONDecodeError:
                response = {'error': 'Invalid JSON'}
                conn.sendall(json.dumps(response).encode('utf-8'))
                return

            # Process request
            response = self._process_request(request)

            # Send response
            conn.sendall(json.dumps(response).encode('utf-8'))

        except Exception as e:
            error_response = {'error': str(e)}
            try:
                conn.sendall(json.dumps(error_response).encode('utf-8'))
            except:
                pass
        finally:
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

        # Authenticate request
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
            except Exception:
                pass  # Don't fail request on logging error

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
        except Exception as e:
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
        except Exception as e:
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
        except Exception as e:
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
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _handle_status(self) -> Dict[str, Any]:
        """Get daemon status"""
        try:
            status = self.daemon.get_status()
            return {'success': True, 'status': status}
        except Exception as e:
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
        except Exception as e:
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
        except Exception as e:
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
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _handle_get_events(self, params: Dict[str, Any]) -> Dict[str, Any]:
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

            return {
                'success': True,
                'events': events_data,
                'count': len(events_data)
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _handle_verify_log(self) -> Dict[str, Any]:
        """Verify event log integrity"""
        try:
            is_valid, error = self.daemon.event_logger.verify_chain()
            return {
                'success': True,
                'valid': is_valid,
                'error': error
            }
        except Exception as e:
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
        except Exception as e:
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
        except Exception as e:
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
            except Exception as e:
                print(f"Warning: Could not read token file: {e}")

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
