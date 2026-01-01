"""
Cluster Manager - Distributed Boundary Daemon Coordination
Manages cluster-wide boundary mode synchronization and distributed operations.
"""

import json
import socket
import threading
import time
import uuid
import logging
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
from typing import Optional, Dict, List, Callable

logger = logging.getLogger(__name__)

from ..policy_engine import BoundaryMode
from ..tripwires import TripwireViolation
from .coordinators import Coordinator, FileCoordinator


@dataclass
class ClusterNode:
    """Information about a node in the cluster"""
    node_id: str
    hostname: str
    mode: str  # BoundaryMode name
    last_heartbeat: float
    violations: int
    lockdown: bool
    metadata: Dict

    def is_healthy(self, timeout: int = 30) -> bool:
        """Check if node is healthy based on heartbeat"""
        return (time.time() - self.last_heartbeat) < timeout


@dataclass
class ClusterState:
    """Overall cluster state"""
    nodes: Dict[str, ClusterNode]
    cluster_mode: str  # Most restrictive mode across all nodes
    total_violations: int
    last_updated: float


class ClusterSyncPolicy(Enum):
    """Policy for how modes are synchronized across the cluster"""
    MOST_RESTRICTIVE = "most_restrictive"  # Use the strictest mode (default)
    LEAST_RESTRICTIVE = "least_restrictive"  # Use the most permissive mode
    MAJORITY = "majority"  # Use the mode used by majority of nodes
    LEADER = "leader"  # Follow a designated leader node


class ClusterManager:
    """
    Manages distributed boundary daemon cluster.

    Coordinates boundary modes, tripwire violations, and health across
    multiple daemon instances.
    """

    def __init__(self, daemon, coordinator: Coordinator,
                 node_id: Optional[str] = None,
                 sync_policy: ClusterSyncPolicy = ClusterSyncPolicy.MOST_RESTRICTIVE):
        """
        Initialize cluster manager.

        Args:
            daemon: Reference to BoundaryDaemon instance
            coordinator: Coordinator backend (FileCoordinator, EtcdCoordinator, etc.)
            node_id: Unique node identifier (generated if not provided)
            sync_policy: Policy for mode synchronization
        """
        self.daemon = daemon
        self.coordinator = coordinator
        self.node_id = node_id or self._generate_node_id()
        self.sync_policy = sync_policy

        # Node state
        self.hostname = socket.gethostname()
        self.is_running = False
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._sync_thread: Optional[threading.Thread] = None

        # Callbacks
        self._mode_change_callbacks: Dict[int, Callable] = {}
        self._violation_callbacks: Dict[int, Callable] = {}
        self._next_callback_id = 0
        self._callback_lock = threading.Lock()

        logger.info(f"ClusterManager initialized: node_id={self.node_id}, hostname={self.hostname}")

    def _generate_node_id(self) -> str:
        """Generate unique node ID"""
        return f"node-{uuid.uuid4().hex[:8]}"

    def start(self):
        """Start cluster coordination"""
        if self.is_running:
            return

        self.is_running = True

        # Register node
        self._register_node()

        # Start heartbeat thread
        self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._heartbeat_thread.start()

        # Start sync thread
        self._sync_thread = threading.Thread(target=self._sync_loop, daemon=True)
        self._sync_thread.start()

        logger.info(f"Cluster coordination started for node {self.node_id}")

    def stop(self):
        """Stop cluster coordination and cleanup resources"""
        if not self.is_running:
            return

        self.is_running = False

        # Deregister node
        self._deregister_node()

        # Clear callbacks to prevent memory leaks
        with self._callback_lock:
            self._mode_change_callbacks.clear()
            self._violation_callbacks.clear()

        logger.info(f"Cluster coordination stopped for node {self.node_id}")

    def register_mode_change_callback(self, callback: Callable) -> int:
        """Register a callback for mode changes.

        Returns:
            Callback ID that can be used to unregister the callback
        """
        with self._callback_lock:
            callback_id = self._next_callback_id
            self._next_callback_id += 1
            self._mode_change_callbacks[callback_id] = callback
            return callback_id

    def unregister_mode_change_callback(self, callback_id: int) -> bool:
        """Unregister a previously registered mode change callback.

        Returns:
            True if callback was found and removed, False otherwise
        """
        with self._callback_lock:
            if callback_id in self._mode_change_callbacks:
                del self._mode_change_callbacks[callback_id]
                return True
            return False

    def register_violation_callback(self, callback: Callable) -> int:
        """Register a callback for violations.

        Returns:
            Callback ID that can be used to unregister the callback
        """
        with self._callback_lock:
            callback_id = self._next_callback_id
            self._next_callback_id += 1
            self._violation_callbacks[callback_id] = callback
            return callback_id

    def unregister_violation_callback(self, callback_id: int) -> bool:
        """Unregister a previously registered violation callback.

        Returns:
            True if callback was found and removed, False otherwise
        """
        with self._callback_lock:
            if callback_id in self._violation_callbacks:
                del self._violation_callbacks[callback_id]
                return True
            return False

    def _register_node(self):
        """Register this node in the cluster"""
        node_data = {
            'node_id': self.node_id,
            'hostname': self.hostname,
            'mode': self.daemon.policy_engine.current_mode.name,
            'last_heartbeat': time.time(),
            'violations': self.daemon.tripwire_system.get_violation_count(),
            'lockdown': self.daemon.tripwire_system.lockdown_manager.is_locked_down,
            'metadata': {
                'version': '1.0',
                'started_at': datetime.utcnow().isoformat()
            }
        }

        key = f'/boundary/nodes/{self.node_id}'
        self.coordinator.put(key, json.dumps(node_data), ttl=60)
        logger.info(f"Node {self.node_id} registered in cluster")

    def _deregister_node(self):
        """Remove this node from the cluster"""
        key = f'/boundary/nodes/{self.node_id}'
        self.coordinator.delete(key)
        logger.info(f"Node {self.node_id} deregistered from cluster")

    def _heartbeat_loop(self):
        """Send periodic heartbeats to cluster"""
        while self.is_running:
            try:
                self._send_heartbeat()
                time.sleep(10)  # Heartbeat every 10 seconds
            except Exception as e:
                logger.error(f"Error in heartbeat loop: {e}")
                time.sleep(10)

    def _send_heartbeat(self):
        """Send a single heartbeat"""
        node_data = {
            'node_id': self.node_id,
            'hostname': self.hostname,
            'mode': self.daemon.policy_engine.current_mode.name,
            'last_heartbeat': time.time(),
            'violations': self.daemon.tripwire_system.get_violation_count(),
            'lockdown': self.daemon.tripwire_system.lockdown_manager.is_locked_down,
            'metadata': {
                'version': '1.0'
            }
        }

        key = f'/boundary/nodes/{self.node_id}'
        self.coordinator.put(key, json.dumps(node_data), ttl=60)

    def _sync_loop(self):
        """Periodically sync with cluster state"""
        while self.is_running:
            try:
                self._sync_with_cluster()
                time.sleep(5)  # Sync every 5 seconds
            except Exception as e:
                logger.error(f"Error in sync loop: {e}")
                time.sleep(5)

    def _sync_with_cluster(self):
        """Synchronize local state with cluster"""
        cluster_state = self.get_cluster_state()

        # Check if we need to change mode based on cluster
        cluster_mode_name = cluster_state.cluster_mode
        current_mode_name = self.daemon.policy_engine.current_mode.name

        if cluster_mode_name != current_mode_name:
            logger.warning(f"Cluster mode mismatch: local={current_mode_name}, cluster={cluster_mode_name}")
            # Optionally auto-sync (based on policy)
            if self.sync_policy == ClusterSyncPolicy.MOST_RESTRICTIVE:
                # Let cluster dictate mode
                try:
                    new_mode = BoundaryMode[cluster_mode_name]
                    if new_mode != self.daemon.policy_engine.current_mode:
                        logger.info(f"Syncing to cluster mode: {cluster_mode_name}")
                        # Trigger mode change callbacks
                        with self._callback_lock:
                            callbacks = list(self._mode_change_callbacks.values())
                        for callback in callbacks:
                            try:
                                callback(new_mode)
                            except Exception as e:
                                logger.error(f"Mode change callback error: {e}")
                except Exception as e:
                    logger.error(f"Error syncing mode: {e}")

    def broadcast_mode_change(self, mode: BoundaryMode):
        """
        Broadcast a mode change to the cluster.

        Args:
            mode: The new boundary mode
        """
        mode_data = {
            'mode': mode.name,
            'node_id': self.node_id,
            'timestamp': time.time(),
            'operator': 'cluster'
        }

        key = f'/boundary/cluster/mode'
        self.coordinator.put(key, json.dumps(mode_data))
        logger.info(f"Broadcast mode change to cluster: {mode.name}")

    def report_violation(self, violation: TripwireViolation):
        """
        Report a tripwire violation to the cluster.

        Args:
            violation: The tripwire violation
        """
        violation_data = {
            'node_id': self.node_id,
            'violation_type': violation.violation_type.value,
            'timestamp': violation.timestamp,
            'details': violation.details
        }

        key = f'/boundary/violations/{self.node_id}/{int(time.time() * 1000)}'
        self.coordinator.put(key, json.dumps(violation_data), ttl=3600)  # Keep for 1 hour

        # Trigger violation callbacks
        with self._callback_lock:
            callbacks = list(self._violation_callbacks.values())
        for callback in callbacks:
            try:
                callback(violation)
            except Exception as e:
                logger.error(f"Violation callback error: {e}")

        logger.info(f"Reported violation to cluster: {violation.violation_type.value}")

    def get_cluster_state(self) -> ClusterState:
        """
        Get the current cluster state.

        Returns:
            ClusterState with all nodes and overall status
        """
        # Get all nodes
        nodes_data = self.coordinator.get_prefix('/boundary/nodes/')

        nodes = {}
        for key, value in nodes_data.items():
            try:
                node_dict = json.loads(value)
                node = ClusterNode(**node_dict)
                nodes[node.node_id] = node
            except Exception as e:
                logger.error(f"Error parsing node data from {key}: {e}")

        # Calculate cluster mode based on sync policy
        cluster_mode = self._calculate_cluster_mode(nodes)

        # Calculate total violations
        total_violations = sum(node.violations for node in nodes.values())

        return ClusterState(
            nodes=nodes,
            cluster_mode=cluster_mode,
            total_violations=total_violations,
            last_updated=time.time()
        )

    def _calculate_cluster_mode(self, nodes: Dict[str, ClusterNode]) -> str:
        """Calculate the cluster-wide mode based on sync policy"""
        if not nodes:
            return BoundaryMode.OPEN.name

        modes = [BoundaryMode[node.mode] for node in nodes.values()]

        if self.sync_policy == ClusterSyncPolicy.MOST_RESTRICTIVE:
            # Return the most restrictive (highest value)
            return max(modes).name
        elif self.sync_policy == ClusterSyncPolicy.LEAST_RESTRICTIVE:
            # Return the least restrictive (lowest value)
            return min(modes).name
        elif self.sync_policy == ClusterSyncPolicy.MAJORITY:
            # Return the mode used by majority
            mode_counts = {}
            for mode in modes:
                mode_counts[mode] = mode_counts.get(mode, 0) + 1
            majority_mode = max(mode_counts.items(), key=lambda x: x[1])[0]
            return majority_mode.name
        else:
            return BoundaryMode.OPEN.name

    def get_healthy_nodes(self) -> List[ClusterNode]:
        """
        Get list of healthy nodes in the cluster.

        Returns:
            List of ClusterNode instances that are healthy
        """
        cluster_state = self.get_cluster_state()
        return [node for node in cluster_state.nodes.values() if node.is_healthy()]

    def get_violations(self) -> List[Dict]:
        """
        Get all recent violations from the cluster.

        Returns:
            List of violation dictionaries
        """
        violations_data = self.coordinator.get_prefix('/boundary/violations/')

        violations = []
        for key, value in violations_data.items():
            try:
                violation = json.loads(value)
                violations.append(violation)
            except Exception as e:
                logger.error(f"Error parsing violation from {key}: {e}")

        # Sort by timestamp (newest first)
        violations.sort(key=lambda v: v.get('timestamp', 0), reverse=True)

        return violations

    def on_mode_change(self, callback: Callable):
        """Register a callback for cluster mode changes"""
        self._mode_change_callbacks.append(callback)

    def on_violation(self, callback: Callable):
        """Register a callback for cluster violations"""
        self._violation_callbacks.append(callback)

    def get_cluster_summary(self) -> str:
        """
        Get a human-readable summary of the cluster.

        Returns:
            Formatted string with cluster information
        """
        state = self.get_cluster_state()

        summary = []
        summary.append(f"Cluster Summary")
        summary.append(f"===============")
        summary.append(f"Total Nodes: {len(state.nodes)}")
        summary.append(f"Healthy Nodes: {len(self.get_healthy_nodes())}")
        summary.append(f"Cluster Mode: {state.cluster_mode}")
        summary.append(f"Total Violations: {state.total_violations}")
        summary.append(f"\nNodes:")

        for node in state.nodes.values():
            status = "✓" if node.is_healthy() else "✗"
            lockdown_str = " [LOCKDOWN]" if node.lockdown else ""
            summary.append(f"  {status} {node.node_id} ({node.hostname}): {node.mode}{lockdown_str}")

        return "\n".join(summary)


if __name__ == '__main__':
    # Test cluster manager
    print("Testing Cluster Manager...")

    # Create a mock daemon class for testing
    class MockDaemon:
        class MockPolicyEngine:
            current_mode = BoundaryMode.OPEN

        class MockTripwireSystem:
            class MockLockdownManager:
                is_locked_down = False

            lockdown_manager = MockLockdownManager()

            def get_violation_count(self):
                return 0

        policy_engine = MockPolicyEngine()
        tripwire_system = MockTripwireSystem()

    # Create coordinator
    import tempfile
    test_dir = tempfile.mkdtemp(prefix="boundary-cluster-test-")
    coordinator = FileCoordinator(test_dir)

    # Create cluster manager
    daemon = MockDaemon()
    cluster_mgr = ClusterManager(daemon, coordinator)

    # Start coordination
    cluster_mgr.start()

    # Wait a bit for heartbeat
    time.sleep(2)

    # Print cluster state
    print("\n" + cluster_mgr.get_cluster_summary())

    # Broadcast mode change
    cluster_mgr.broadcast_mode_change(BoundaryMode.RESTRICTED)

    # Wait and check again
    time.sleep(2)
    print("\n" + cluster_mgr.get_cluster_summary())

    # Stop
    cluster_mgr.stop()

    print("\nCluster manager test complete.")
