"""
Boundary API - Unix Socket Interface
Provides local-only socket API for other Agent OS components.
"""

import json
import os
import socket
import threading
from typing import Optional, Dict, Any

from daemon.policy_engine import BoundaryMode, Operator, MemoryClass


class BoundaryAPIServer:
    """
    Unix socket API server for boundary daemon.
    Provides read-only status and command interface.
    """

    def __init__(self, daemon, socket_path: str = './api/boundary.sock'):
        """
        Initialize API server.

        Args:
            daemon: Reference to BoundaryDaemon instance
            socket_path: Path to Unix socket
        """
        self.daemon = daemon
        self.socket_path = socket_path
        self._running = False
        self._server_thread: Optional[threading.Thread] = None
        self._socket: Optional[socket.socket] = None

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
            "command": "status|check_recall|check_tool|set_mode|get_events",
            "params": {...}
        }
        """
        command = request.get('command')
        params = request.get('params', {})

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

        else:
            return {'error': f'Unknown command: {command}'}

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


class BoundaryAPIClient:
    """
    Client for communicating with the Boundary Daemon API.
    Used by other Agent OS components (Memory Vault, synth-mind, etc.)
    """

    def __init__(self, socket_path: str = './api/boundary.sock'):
        """
        Initialize API client.

        Args:
            socket_path: Path to Unix socket
        """
        self.socket_path = socket_path

    def _send_request(self, command: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Send a request to the daemon"""
        request = {
            'command': command,
            'params': params or {}
        }

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

    print("\nAPI client test complete.")
