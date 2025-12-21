#!/usr/bin/env python3
"""
Cluster Demo - Demonstration of distributed boundary daemon coordination
Simulates multiple daemon instances coordinating via a shared coordinator.
"""

import sys
import time
import argparse
from daemon.distributed.cluster_manager import ClusterManager, ClusterSyncPolicy
from daemon.distributed.coordinators import FileCoordinator
from daemon.policy_engine import BoundaryMode


class MockDaemon:
    """Mock boundary daemon for testing cluster coordination"""

    class MockPolicyEngine:
        def __init__(self, initial_mode=BoundaryMode.OPEN):
            self.current_mode = initial_mode

    class MockTripwireSystem:
        class MockLockdownManager:
            is_locked_down = False

        lockdown_manager = MockLockdownManager()
        _violation_count = 0

        def get_violation_count(self):
            return self._violation_count

        def add_violation(self):
            self._violation_count += 1

    def __init__(self, node_id: str, initial_mode=BoundaryMode.OPEN):
        self.node_id = node_id
        self.policy_engine = self.MockPolicyEngine(initial_mode)
        self.tripwire_system = self.MockTripwireSystem()


def simulate_cluster(num_nodes: int = 3, data_dir: str = '/tmp/boundary-cluster'):
    """
    Simulate a cluster of boundary daemons.

    Args:
        num_nodes: Number of nodes to simulate
        data_dir: Directory for cluster state
    """
    print(f"\n{'='*70}")
    print(f"Simulating {num_nodes}-node Boundary Daemon Cluster")
    print(f"{'='*70}\n")

    # Create coordinator
    coordinator = FileCoordinator(data_dir)

    # Create mock daemons and cluster managers
    nodes = []
    for i in range(num_nodes):
        node_id = f"demo-node-{i+1}"
        daemon = MockDaemon(node_id, initial_mode=BoundaryMode.OPEN)
        cluster_mgr = ClusterManager(
            daemon,
            coordinator,
            node_id=node_id,
            sync_policy=ClusterSyncPolicy.MOST_RESTRICTIVE
        )
        nodes.append((daemon, cluster_mgr))

    # Start all nodes
    print("Starting all nodes...")
    for daemon, cluster_mgr in nodes:
        cluster_mgr.start()

    time.sleep(2)

    # Show initial cluster state
    print("\n" + nodes[0][1].get_cluster_summary())

    # Simulate mode change on one node
    print(f"\n{'='*70}")
    print("Scenario 1: Node 1 changes to RESTRICTED mode")
    print(f"{'='*70}\n")

    nodes[0][0].policy_engine.current_mode = BoundaryMode.RESTRICTED
    nodes[0][1].broadcast_mode_change(BoundaryMode.RESTRICTED)

    time.sleep(2)
    print("\n" + nodes[0][1].get_cluster_summary())

    # Simulate violation on another node
    print(f"\n{'='*70}")
    print("Scenario 2: Node 2 reports a violation")
    print(f"{'='*70}\n")

    from daemon.tripwires import TripwireViolation, ViolationType
    violation = TripwireViolation(
        violation_id="test-violation-1",
        timestamp=str(time.time()),
        violation_type=ViolationType.NETWORK_IN_AIRGAP,
        details="Simulated network violation in AIRGAP mode",
        current_mode=BoundaryMode.AIRGAP,
        environment_snapshot={},
        auto_lockdown=True
    )

    nodes[1][0].tripwire_system.add_violation()
    nodes[1][1].report_violation(violation)

    time.sleep(2)
    print("\n" + nodes[1][1].get_cluster_summary())

    # Show all violations
    print(f"\n{'='*70}")
    print("Recent Cluster Violations")
    print(f"{'='*70}\n")

    violations = nodes[0][1].get_violations()
    for v in violations:
        print(f"  [{v['node_id']}] {v['violation_type']}: {v['details']}")

    # Simulate escalation to AIRGAP
    print(f"\n{'='*70}")
    print("Scenario 3: Node 3 escalates to AIRGAP mode (cluster follows)")
    print(f"{'='*70}\n")

    nodes[2][0].policy_engine.current_mode = BoundaryMode.AIRGAP
    nodes[2][1].broadcast_mode_change(BoundaryMode.AIRGAP)

    time.sleep(2)
    print("\n" + nodes[2][1].get_cluster_summary())

    # Show healthy nodes
    print(f"\n{'='*70}")
    print("Cluster Health Check")
    print(f"{'='*70}\n")

    healthy = nodes[0][1].get_healthy_nodes()
    print(f"Healthy nodes: {len(healthy)}/{len(nodes)}")
    for node in healthy:
        print(f"  ✓ {node.node_id} ({node.hostname})")

    # Cleanup
    print(f"\n{'='*70}")
    print("Stopping all nodes...")
    print(f"{'='*70}\n")

    for daemon, cluster_mgr in nodes:
        cluster_mgr.stop()

    print("\nCluster simulation complete.\n")


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='Boundary Daemon Cluster Demonstration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cluster_demo.py                    # Simulate 3-node cluster
  python cluster_demo.py --nodes 5          # Simulate 5-node cluster
  python cluster_demo.py --data-dir /tmp/my-cluster  # Use custom data directory
"""
    )

    parser.add_argument('--nodes', type=int, default=3,
                       help='Number of nodes to simulate (default: 3)')
    parser.add_argument('--data-dir', type=str, default='/tmp/boundary-cluster',
                       help='Directory for cluster state (default: /tmp/boundary-cluster)')

    args = parser.parse_args()

    if args.nodes < 1:
        print("Error: Number of nodes must be at least 1")
        return 1

    try:
        simulate_cluster(args.nodes, args.data_dir)
        return 0
    except KeyboardInterrupt:
        print("\n\nSimulation interrupted by user.\n")
        return 130
    except Exception as e:
        print(f"\nError: {e}\n")
        return 1


if __name__ == '__main__':
    sys.exit(main())
