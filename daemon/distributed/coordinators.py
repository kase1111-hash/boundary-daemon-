"""
Coordinator Backends - Pluggable cluster coordination backends
Provides abstract interface and implementations (file-based, etcd, consul, etc.)
"""

import json
import os
import time
import threading
import fcntl
import logging
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List
from pathlib import Path

logger = logging.getLogger(__name__)


class Coordinator(ABC):
    """
    Abstract coordinator interface for cluster state management.
    Implementations can use etcd, consul, file system, or other backends.
    """

    @abstractmethod
    def put(self, key: str, value: str, ttl: Optional[int] = None) -> bool:
        """
        Store a key-value pair.

        Args:
            key: The key path (e.g., '/boundary/nodes/node1')
            value: The value to store (usually JSON)
            ttl: Time-to-live in seconds (optional)

        Returns:
            True if successful
        """
        pass

    @abstractmethod
    def get(self, key: str) -> Optional[str]:
        """
        Retrieve a value by key.

        Args:
            key: The key path

        Returns:
            The value, or None if not found
        """
        pass

    @abstractmethod
    def get_prefix(self, prefix: str) -> Dict[str, str]:
        """
        Get all keys with a given prefix.

        Args:
            prefix: The key prefix (e.g., '/boundary/nodes/')

        Returns:
            Dictionary of key-value pairs
        """
        pass

    @abstractmethod
    def delete(self, key: str) -> bool:
        """
        Delete a key.

        Args:
            key: The key to delete

        Returns:
            True if successful
        """
        pass

    @abstractmethod
    def watch(self, key: str, callback):
        """
        Watch a key for changes (optional, not all backends support this).

        Args:
            key: The key to watch
            callback: Function to call when key changes
        """
        pass


class FileCoordinator(Coordinator):
    """
    File-based coordinator for development and testing.
    Stores cluster state in JSON files on a shared filesystem.

    WARNING: This is NOT suitable for production use. Use etcd/consul in production.
    """

    def __init__(self, data_dir: str = '/tmp/boundary-cluster'):
        """
        Initialize file coordinator.

        Args:
            data_dir: Directory to store cluster state files
        """
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.state_file = self.data_dir / 'cluster_state.json'
        self.lock_file = self.data_dir / 'cluster_state.lock'
        self._state: Dict[str, Any] = {}
        self._load_state()
        self._ttl_thread = threading.Thread(target=self._ttl_cleanup, daemon=True)
        self._ttl_thread.start()

    def _load_state(self):
        """Load state from file"""
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r') as f:
                    self._state = json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load cluster state: {e}")
                self._state = {}

    def _save_state(self):
        """Save state to file with locking"""
        try:
            # Use file locking to prevent concurrent writes
            with open(self.lock_file, 'w') as lock:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
                try:
                    with open(self.state_file, 'w') as f:
                        json.dump(self._state, f, indent=2)
                        f.flush()
                        os.fsync(f.fileno())
                finally:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        except Exception as e:
            logger.error(f"Error saving cluster state: {e}")

    def put(self, key: str, value: str, ttl: Optional[int] = None) -> bool:
        """Store a key-value pair with optional TTL"""
        try:
            entry = {
                'value': value,
                'timestamp': time.time()
            }
            if ttl:
                entry['expires'] = time.time() + ttl

            self._state[key] = entry
            self._save_state()
            return True
        except Exception as e:
            logger.error(f"Error storing key {key}: {e}")
            return False

    def get(self, key: str) -> Optional[str]:
        """Retrieve a value by key"""
        entry = self._state.get(key)
        if not entry:
            return None

        # Check if expired
        if 'expires' in entry and entry['expires'] < time.time():
            self.delete(key)
            return None

        return entry.get('value')

    def get_prefix(self, prefix: str) -> Dict[str, str]:
        """Get all keys with a given prefix"""
        result = {}
        for key, entry in self._state.items():
            if key.startswith(prefix):
                # Check if expired
                if 'expires' in entry and entry['expires'] < time.time():
                    continue
                result[key] = entry.get('value')
        return result

    def delete(self, key: str) -> bool:
        """Delete a key"""
        try:
            if key in self._state:
                del self._state[key]
                self._save_state()
            return True
        except Exception as e:
            logger.error(f"Error deleting key {key}: {e}")
            return False

    def watch(self, key: str, callback):
        """
        Simple watch implementation using polling.
        Not efficient but works for testing.
        """
        def poll():
            last_value = self.get(key)
            while True:
                time.sleep(1)
                current_value = self.get(key)
                if current_value != last_value:
                    callback(current_value)
                    last_value = current_value

        thread = threading.Thread(target=poll, daemon=True)
        thread.start()

    def _ttl_cleanup(self):
        """Background thread to clean up expired entries"""
        while True:
            time.sleep(10)  # Check every 10 seconds
            try:
                expired_keys = []
                for key, entry in self._state.items():
                    if 'expires' in entry and entry['expires'] < time.time():
                        expired_keys.append(key)

                for key in expired_keys:
                    self.delete(key)
            except Exception as e:
                logger.error(f"Error in TTL cleanup: {e}")


# Placeholder for future etcd implementation
class EtcdCoordinator(Coordinator):
    """
    Etcd-based coordinator for production deployments.

    NOTE: Requires etcd3 library to be installed.
    Install with: pip install etcd3
    """

    def __init__(self, host: str = 'localhost', port: int = 2379):
        """
        Initialize etcd coordinator.

        Args:
            host: Etcd server host
            port: Etcd server port
        """
        try:
            import etcd3
            self.client = etcd3.client(host=host, port=port)
        except ImportError:
            raise ImportError(
                "etcd3 library not installed. "
                "Install with: pip install etcd3"
            )

    def put(self, key: str, value: str, ttl: Optional[int] = None) -> bool:
        """Store a key-value pair with optional lease"""
        try:
            if ttl:
                lease = self.client.lease(ttl)
                self.client.put(key, value, lease=lease)
            else:
                self.client.put(key, value)
            return True
        except Exception as e:
            logger.error(f"Error storing key {key}: {e}")
            return False

    def get(self, key: str) -> Optional[str]:
        """Retrieve a value by key"""
        try:
            value, _ = self.client.get(key)
            return value.decode('utf-8') if value else None
        except Exception as e:
            logger.error(f"Error retrieving key {key}: {e}")
            return None

    def get_prefix(self, prefix: str) -> Dict[str, str]:
        """Get all keys with a given prefix"""
        try:
            result = {}
            for value, metadata in self.client.get_prefix(prefix):
                key = metadata.key.decode('utf-8')
                result[key] = value.decode('utf-8')
            return result
        except Exception as e:
            logger.error(f"Error retrieving prefix {prefix}: {e}")
            return {}

    def delete(self, key: str) -> bool:
        """Delete a key"""
        try:
            self.client.delete(key)
            return True
        except Exception as e:
            logger.error(f"Error deleting key {key}: {e}")
            return False

    def watch(self, key: str, callback):
        """Watch a key for changes"""
        def watch_callback(event):
            if event.value:
                callback(event.value.decode('utf-8'))

        events_iterator, cancel = self.client.watch(key)
        for event in events_iterator:
            watch_callback(event)
