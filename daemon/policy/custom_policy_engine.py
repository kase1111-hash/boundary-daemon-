"""
Custom Policy Engine - User-Defined Policy Rules
Allows users to define custom boundary policies using YAML configuration files.
"""

import glob
import logging
import os
import re
import threading
import time
import yaml
from dataclasses import dataclass
from enum import Enum
from typing import Optional, List, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)

from ..policy_engine import PolicyRequest, PolicyDecision, BoundaryMode, MemoryClass
from ..state_monitor import EnvironmentState


class PolicyAction(Enum):
    """Policy action to take when conditions match"""
    ALLOW = "ALLOW"
    DENY = "DENY"


@dataclass
class PolicyRule:
    """A single policy rule"""
    name: str
    condition: Dict[str, Any]
    action: PolicyAction
    priority: int = 100  # Lower = higher priority
    enabled: bool = True
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class CustomPolicyEngine:
    """
    Evaluates user-defined policy rules from YAML files.

    Supports custom conditions based on:
    - Boundary mode
    - Environment state (VPN, network, processes, etc.)
    - Memory classification
    - Tool requirements and patterns
    - Time-based rules
    - Custom metadata
    """

    def __init__(self, policy_dir: str):
        """
        Initialize custom policy engine.

        Args:
            policy_dir: Directory containing YAML policy files
        """
        self.policy_dir = Path(policy_dir)
        self.policies: List[PolicyRule] = []
        self._lock = threading.RLock()
        self._last_reload = 0

        # Ensure directory exists
        self.policy_dir.mkdir(parents=True, exist_ok=True)

        # Load initial policies
        self.reload_policies()

        logger.info(f"CustomPolicyEngine initialized with {len(self.policies)} policies from {policy_dir}")

    def reload_policies(self):
        """Reload all policy files from disk"""
        with self._lock:
            new_policies = []

            # Find all YAML files in policy directory
            pattern = str(self.policy_dir / '*.yaml')
            policy_files = glob.glob(pattern)
            policy_files.extend(glob.glob(str(self.policy_dir / '*.yml')))

            for filepath in policy_files:
                try:
                    policies = self._load_policy_file(filepath)
                    new_policies.extend(policies)
                except Exception as e:
                    logger.error(f"Error loading policy file {filepath}: {e}")

            # Sort by priority (lower number = higher priority)
            new_policies.sort(key=lambda p: p.priority)

            self.policies = new_policies
            self._last_reload = time.time()

            logger.info(f"Reloaded {len(self.policies)} policies from {len(policy_files)} files")

    def _load_policy_file(self, filepath: str) -> List[PolicyRule]:
        """Load policies from a single YAML file"""
        with open(filepath, 'r') as f:
            data = yaml.safe_load(f)

        if not data or 'policies' not in data:
            return []

        rules = []
        for policy_data in data['policies']:
            try:
                rule = PolicyRule(
                    name=policy_data['name'],
                    condition=policy_data.get('condition', {}),
                    action=PolicyAction[policy_data['action']],
                    priority=policy_data.get('priority', 100),
                    enabled=policy_data.get('enabled', True),
                    metadata=policy_data.get('metadata', {})
                )
                rules.append(rule)
            except Exception as e:
                logger.error(f"Error parsing policy '{policy_data.get('name', 'unknown')}': {e}")

        return rules

    def evaluate(self, request: PolicyRequest, env: EnvironmentState,
                 current_mode: BoundaryMode) -> Optional[PolicyDecision]:
        """
        Evaluate custom policies against a request.

        Args:
            request: The policy request (recall/tool/etc.)
            env: Current environment state
            current_mode: Current boundary mode

        Returns:
            PolicyDecision if a rule matches, None to fall through to default policy
        """
        with self._lock:
            for policy in self.policies:
                if not policy.enabled:
                    continue

                if self._matches_condition(policy.condition, request, env, current_mode):
                    # Log which policy matched
                    decision = PolicyDecision.ALLOW if policy.action == PolicyAction.ALLOW else PolicyDecision.DENY
                    logger.info(f"Custom policy matched: '{policy.name}' -> {decision.name}")
                    return decision

        # No custom policy matched - fall through to default
        return None

    def _matches_condition(self, condition: Dict[str, Any],
                          request: PolicyRequest,
                          env: EnvironmentState,
                          current_mode: BoundaryMode) -> bool:
        """
        Check if all conditions in a policy match the current state.

        Returns:
            True if all conditions match, False otherwise
        """
        # Check mode condition
        if 'mode' in condition:
            if not self._check_mode_condition(condition['mode'], current_mode):
                return False

        # Check environment conditions
        if 'environment' in condition:
            if not self._check_environment_condition(condition['environment'], env):
                return False

        # Check memory class condition
        if 'memory_class' in condition:
            if not self._check_memory_class_condition(condition['memory_class'], request):
                return False

        # Check tool conditions
        if 'tool' in condition:
            if not self._check_tool_condition(condition['tool'], request):
                return False

        # Check time-based conditions
        if 'time' in condition:
            if not self._check_time_condition(condition['time']):
                return False

        # All conditions matched
        return True

    def _check_mode_condition(self, mode_condition: Any, current_mode: BoundaryMode) -> bool:
        """Check if mode condition matches"""
        # Support single mode or list of modes
        if isinstance(mode_condition, str):
            mode_condition = [mode_condition]

        # Check if current mode is in the list
        for mode_name in mode_condition:
            try:
                if current_mode == BoundaryMode[mode_name]:
                    return True
            except KeyError:
                logger.warning(f"Invalid mode name in policy: {mode_name}")

        return False

    def _check_environment_condition(self, env_condition: Dict[str, Any],
                                    env: EnvironmentState) -> bool:
        """Check if environment conditions match"""
        # Check VPN status
        if 'vpn_active' in env_condition:
            if env.vpn_active != env_condition['vpn_active']:
                return False

        # Check internet connectivity
        if 'has_internet' in env_condition:
            if env.has_internet != env_condition['has_internet']:
                return False

        # Check network state
        if 'network' in env_condition:
            expected = env_condition['network'].upper()
            if env.network.name != expected:
                return False

        # Check for process patterns
        if 'processes' in env_condition:
            proc_condition = env_condition['processes']
            if not self._check_process_condition(proc_condition, env):
                return False

        # Check USB devices
        if 'usb_devices' in env_condition:
            usb_condition = env_condition['usb_devices']
            if isinstance(usb_condition, dict):
                if 'count_gt' in usb_condition:
                    if len(env.usb_devices) <= usb_condition['count_gt']:
                        return False
                if 'count_lt' in usb_condition:
                    if len(env.usb_devices) >= usb_condition['count_lt']:
                        return False
                if 'any' in usb_condition:
                    if (len(env.usb_devices) > 0) != usb_condition['any']:
                        return False

        # Check external models
        if 'external_models' in env_condition:
            has_external_models = len(env.external_model_endpoints) > 0
            if has_external_models != env_condition['external_models']:
                return False

        return True

    def _check_process_condition(self, proc_condition: Dict[str, Any],
                                 env: EnvironmentState) -> bool:
        """Check if process conditions match"""
        # Get process list (would need to be added to EnvironmentState)
        # For now, check suspicious processes from env
        if 'contains' in proc_condition:
            pattern = proc_condition['contains']
            # Check if pattern appears in suspicious processes
            for proc in env.suspicious_processes:
                if pattern in proc:
                    return True
            return False

        if 'matches' in proc_condition:
            pattern = proc_condition['matches']
            regex = re.compile(pattern)
            for proc in env.suspicious_processes:
                if regex.search(proc):
                    return True
            return False

        return True

    def _check_memory_class_condition(self, mem_condition: Any,
                                     request: PolicyRequest) -> bool:
        """Check if memory class condition matches"""
        # Only apply to recall requests
        if request.memory_class is None:
            return False  # Not a memory request, this policy doesn't match

        # Support single class or list
        if isinstance(mem_condition, str):
            mem_condition = [mem_condition]

        # Check if memory class is in the list
        for class_name in mem_condition:
            try:
                if request.memory_class == MemoryClass[class_name]:
                    return True
            except KeyError:
                logger.warning(f"Invalid memory class in policy: {class_name}")

        return False

    def _check_tool_condition(self, tool_condition: Dict[str, Any],
                             request: PolicyRequest) -> bool:
        """Check if tool conditions match"""
        # Only apply to tool requests
        if request.tool_name is None:
            return False  # Not a tool request, this policy doesn't match

        # Check tool name pattern
        if 'name_pattern' in tool_condition:
            pattern = tool_condition['name_pattern']
            regex = re.compile(pattern)
            if not regex.match(request.tool_name):
                return False

        # Check tool requirements
        if 'requires_network' in tool_condition:
            if request.requires_network != tool_condition['requires_network']:
                return False

        if 'requires_filesystem' in tool_condition:
            if request.requires_filesystem != tool_condition['requires_filesystem']:
                return False

        if 'requires_usb' in tool_condition:
            if request.requires_usb != tool_condition['requires_usb']:
                return False

        return True

    def _check_time_condition(self, time_condition: Dict[str, Any]) -> bool:
        """Check if time-based conditions match"""
        import datetime

        now = datetime.datetime.now()

        # Check day of week
        if 'day_of_week' in time_condition:
            days = time_condition['day_of_week']
            if isinstance(days, str):
                days = [days]
            day_names = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']
            current_day = day_names[now.weekday()]
            if current_day not in [d.lower() for d in days]:
                return False

        # Check time range
        if 'hour_range' in time_condition:
            hour_range = time_condition['hour_range']
            start_hour = hour_range.get('start', 0)
            end_hour = hour_range.get('end', 23)
            if not (start_hour <= now.hour <= end_hour):
                return False

        return True

    def get_enabled_policies(self) -> List[PolicyRule]:
        """Get list of enabled policies"""
        with self._lock:
            return [p for p in self.policies if p.enabled]

    def get_policy_by_name(self, name: str) -> Optional[PolicyRule]:
        """Find a policy by name"""
        with self._lock:
            for policy in self.policies:
                if policy.name == name:
                    return policy
        return None

    def validate_policy_file(self, filepath: str) -> tuple[bool, Optional[str]]:
        """
        Validate a policy file without loading it.

        Returns:
            (is_valid, error_message)
        """
        try:
            with open(filepath, 'r') as f:
                data = yaml.safe_load(f)

            if not data:
                return (False, "Empty file")

            if 'policies' not in data:
                return (False, "Missing 'policies' key")

            if not isinstance(data['policies'], list):
                return (False, "'policies' must be a list")

            # Validate each policy
            for i, policy in enumerate(data['policies']):
                if 'name' not in policy:
                    return (False, f"Policy {i} missing 'name'")

                if 'action' not in policy:
                    return (False, f"Policy '{policy['name']}' missing 'action'")

                try:
                    PolicyAction[policy['action']]
                except KeyError:
                    return (False, f"Policy '{policy['name']}' has invalid action: {policy['action']}")

            return (True, None)

        except yaml.YAMLError as e:
            return (False, f"YAML parse error: {e}")
        except Exception as e:
            return (False, f"Error: {e}")


if __name__ == '__main__':
    # Test custom policy engine
    print("Testing Custom Policy Engine...")

    import tempfile
    import shutil

    # Create temporary policy directory
    temp_dir = tempfile.mkdtemp()
    policy_dir = Path(temp_dir) / 'policies.d'
    policy_dir.mkdir(parents=True)

    # Create a test policy file
    test_policy = """
policies:
  - name: "Block API keys in AIRGAP"
    condition:
      mode: [AIRGAP, COLDROOM]
      environment:
        external_models: true
    action: DENY
    priority: 10

  - name: "Require VPN for confidential memories"
    condition:
      memory_class: [CONFIDENTIAL, SECRET]
      environment:
        vpn_active: false
    action: DENY
    priority: 20

  - name: "Allow filesystem tools in dev mode"
    condition:
      mode: [OPEN, RESTRICTED]
      tool:
        requires_filesystem: true
        name_pattern: "^(cat|ls|grep)$"
    action: ALLOW
    priority: 30
"""

    with open(policy_dir / 'test.yaml', 'w') as f:
        f.write(test_policy)

    # Create engine
    engine = CustomPolicyEngine(str(policy_dir))

    print(f"\nLoaded {len(engine.policies)} policies:")
    for p in engine.policies:
        print(f"  [{p.priority}] {p.name} -> {p.action.name}")

    # Test validation
    print("\nValidating policy file...")
    is_valid, error = engine.validate_policy_file(str(policy_dir / 'test.yaml'))
    print(f"Valid: {is_valid}")
    if error:
        print(f"Error: {error}")

    # Cleanup
    shutil.rmtree(temp_dir)

    print("\nCustom policy engine test complete.")
