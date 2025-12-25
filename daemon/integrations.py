"""
Integration Interfaces - Memory Vault, Tool Enforcement, Message Checking, and Ceremony
Provides high-level interfaces for integrating with other Agent OS components.
"""

import time
import getpass
from typing import Optional, Callable, Union, List, Dict, Any
from datetime import datetime, timedelta

from .policy_engine import MemoryClass, BoundaryMode
from .event_logger import EventLogger, EventType

# Import message checking components
try:
    from .messages import (
        MessageChecker,
        MessageSource,
        MessageCheckResult,
        NatLangChainEntry,
        AgentOSMessage,
    )
    MESSAGE_CHECKER_AVAILABLE = True
except ImportError:
    MESSAGE_CHECKER_AVAILABLE = False
    MessageChecker = None
    MessageSource = None
    MessageCheckResult = None
    NatLangChainEntry = None
    AgentOSMessage = None


class RecallGate:
    """
    Memory Vault integration interface.
    Memory Vault MUST call check_recall() before returning any memory.
    """

    def __init__(self, daemon):
        """
        Initialize recall gate.

        Args:
            daemon: Reference to BoundaryDaemon instance
        """
        self.daemon = daemon

    def check_recall(self, memory_class: MemoryClass, memory_id: str = "") -> tuple[bool, str]:
        """
        Check if memory recall is permitted.

        This is the mandatory gating function that Memory Vault must call.

        Args:
            memory_class: Classification level of the memory
            memory_id: Optional identifier for the memory

        Returns:
            (permitted, reason)
        """
        permitted, reason = self.daemon.check_recall_permission(memory_class)

        # Log additional context if memory_id provided
        if memory_id:
            self.daemon.event_logger.log_event(
                EventType.RECALL_ATTEMPT,
                f"Memory recall: {memory_id} (class {memory_class.value})",
                metadata={
                    'memory_id': memory_id,
                    'memory_class': memory_class.value,
                    'permitted': permitted
                }
            )

        return (permitted, reason)

    def get_minimum_mode(self, memory_class: MemoryClass) -> BoundaryMode:
        """
        Get the minimum boundary mode required for a memory class.

        Args:
            memory_class: Memory classification level

        Returns:
            Minimum required boundary mode
        """
        return self.daemon.policy_engine.get_minimum_mode_for_memory(memory_class)

    def is_accessible(self, memory_class: MemoryClass) -> bool:
        """
        Quick check if memory class is accessible in current mode.

        Args:
            memory_class: Memory classification level

        Returns:
            True if accessible
        """
        permitted, _ = self.daemon.check_recall_permission(memory_class)
        return permitted


class ToolGate:
    """
    Tool execution enforcement interface.
    Agent-OS MUST call check_tool() before executing any tool.
    """

    def __init__(self, daemon):
        """
        Initialize tool gate.

        Args:
            daemon: Reference to BoundaryDaemon instance
        """
        self.daemon = daemon

    def check_tool(self, tool_name: str, requires_network: bool = False,
                   requires_filesystem: bool = False,
                   requires_usb: bool = False,
                   context: Optional[dict] = None) -> tuple[bool, str]:
        """
        Check if tool execution is permitted.

        Args:
            tool_name: Name of the tool to execute
            requires_network: Tool needs network access
            requires_filesystem: Tool needs filesystem access
            requires_usb: Tool needs USB access
            context: Additional context for logging

        Returns:
            (permitted, reason)
        """
        permitted, reason = self.daemon.check_tool_permission(
            tool_name,
            requires_network=requires_network,
            requires_filesystem=requires_filesystem,
            requires_usb=requires_usb
        )

        # Log additional context if provided
        if context:
            self.daemon.event_logger.log_event(
                EventType.TOOL_REQUEST,
                f"Tool execution: {tool_name}",
                metadata={
                    'tool_name': tool_name,
                    'permitted': permitted,
                    'context': context
                }
            )

        return (permitted, reason)

    def get_allowed_tools(self) -> dict:
        """
        Get information about which tool categories are allowed in current mode.

        Returns:
            Dictionary with allowed capabilities
        """
        current_mode = self.daemon.policy_engine.get_current_mode()
        env_state = self.daemon.state_monitor.get_current_state()

        capabilities = {
            'network_tools': False,
            'filesystem_tools': False,
            'usb_tools': False,
            'display_only': False
        }

        if current_mode == BoundaryMode.COLDROOM:
            capabilities['display_only'] = True
        elif current_mode == BoundaryMode.AIRGAP:
            capabilities['filesystem_tools'] = True
        elif current_mode <= BoundaryMode.TRUSTED:
            capabilities['network_tools'] = env_state and env_state.network.value == 'offline'
            capabilities['filesystem_tools'] = True
        else:  # OPEN, RESTRICTED
            capabilities['network_tools'] = True
            capabilities['filesystem_tools'] = True

        return capabilities


class MessageGate:
    """
    Message validation interface for NatLangChain and Agent-OS.
    All messages MUST pass through this gate for content validation.
    """

    def __init__(self, daemon, strict_mode: bool = False):
        """
        Initialize message gate.

        Args:
            daemon: Reference to BoundaryDaemon instance
            strict_mode: If True, block on any potential issue
        """
        self.daemon = daemon
        self.strict_mode = strict_mode

        if MESSAGE_CHECKER_AVAILABLE and MessageChecker:
            self.checker = MessageChecker(daemon=daemon, strict_mode=strict_mode)
        else:
            self.checker = None

    def check_natlangchain(
        self,
        author: str,
        intent: str,
        timestamp: str,
        signature: Optional[str] = None,
        previous_hash: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> tuple[bool, str, Optional[Dict]]:
        """
        Check a NatLangChain blockchain entry.

        Args:
            author: Entry author
            intent: Intent description (prose)
            timestamp: Entry timestamp (ISO format)
            signature: Optional cryptographic signature
            previous_hash: Optional hash of previous entry
            metadata: Optional additional metadata

        Returns:
            (permitted, reason, result_data)
        """
        if not self.checker:
            return (False, "Message checker not available", None)

        entry = NatLangChainEntry(
            author=author,
            intent=intent,
            timestamp=timestamp,
            signature=signature,
            previous_hash=previous_hash,
            metadata=metadata or {}
        )

        result = self.checker.check_natlangchain_entry(entry)

        # Log the check
        self.daemon.event_logger.log_event(
            EventType.MESSAGE_CHECK,
            f"NatLangChain entry check: {'allowed' if result.allowed else 'blocked'}",
            metadata={
                'source': 'natlangchain',
                'author': author,
                'allowed': result.allowed,
                'result_type': result.result_type.value,
                'violations': result.violations,
            }
        )

        return (result.allowed, result.reason, result.to_dict())

    def check_agentos(
        self,
        sender_agent: str,
        recipient_agent: str,
        content: str,
        message_type: str = 'request',
        authority_level: int = 0,
        timestamp: Optional[str] = None,
        requires_consent: bool = False,
        metadata: Optional[Dict[str, Any]] = None
    ) -> tuple[bool, str, Optional[Dict]]:
        """
        Check an Agent-OS inter-agent message.

        Args:
            sender_agent: Sending agent identifier
            recipient_agent: Receiving agent identifier
            content: Message content
            message_type: Type of message (request, response, notification, command)
            authority_level: Authority level (0-5)
            timestamp: Message timestamp (ISO format)
            requires_consent: Whether consent is required
            metadata: Optional additional metadata

        Returns:
            (permitted, reason, result_data)
        """
        if not self.checker:
            return (False, "Message checker not available", None)

        if timestamp is None:
            timestamp = datetime.utcnow().isoformat() + "Z"

        message = AgentOSMessage(
            sender_agent=sender_agent,
            recipient_agent=recipient_agent,
            content=content,
            message_type=message_type,
            authority_level=authority_level,
            timestamp=timestamp,
            requires_consent=requires_consent,
            metadata=metadata or {}
        )

        result = self.checker.check_agentos_message(message)

        # Log the check
        self.daemon.event_logger.log_event(
            EventType.MESSAGE_CHECK,
            f"Agent-OS message check: {'allowed' if result.allowed else 'blocked'}",
            metadata={
                'source': 'agent_os',
                'sender': sender_agent,
                'recipient': recipient_agent,
                'message_type': message_type,
                'authority_level': authority_level,
                'allowed': result.allowed,
                'result_type': result.result_type.value,
                'violations': result.violations,
            }
        )

        return (result.allowed, result.reason, result.to_dict())

    def check_message(
        self,
        content: str,
        source: str = 'unknown',
        context: Optional[Dict[str, Any]] = None
    ) -> tuple[bool, str, Optional[Dict]]:
        """
        Check any message content.

        Args:
            content: Message content to check
            source: Source identifier ('natlangchain', 'agent_os', or other)
            context: Optional additional context

        Returns:
            (permitted, reason, result_data)
        """
        if not self.checker:
            return (False, "Message checker not available", None)

        # Map source string to enum
        source_map = {
            'natlangchain': MessageSource.NATLANGCHAIN,
            'agent_os': MessageSource.AGENT_OS,
            'agent-os': MessageSource.AGENT_OS,
            'agentos': MessageSource.AGENT_OS,
        }
        msg_source = source_map.get(source.lower(), MessageSource.UNKNOWN)

        result = self.checker.check_message(content, msg_source, context)

        # Log the check
        self.daemon.event_logger.log_event(
            EventType.MESSAGE_CHECK,
            f"Message check ({source}): {'allowed' if result.allowed else 'blocked'}",
            metadata={
                'source': source,
                'allowed': result.allowed,
                'result_type': result.result_type.value,
                'violations': result.violations,
                'has_redaction': result.redacted_content is not None,
            }
        )

        return (result.allowed, result.reason, result.to_dict())

    def is_available(self) -> bool:
        """Check if message checking is available"""
        return self.checker is not None


class CeremonyManager:
    """
    Human override ceremony system.
    Implements multi-step confirmation with cooldown for critical operations.
    """

    def __init__(self, daemon, cooldown_seconds: int = 30):
        """
        Initialize ceremony manager.

        Args:
            daemon: Reference to BoundaryDaemon instance
            cooldown_seconds: Delay between override steps
        """
        self.daemon = daemon
        self.cooldown_seconds = cooldown_seconds
        self._last_ceremony: Optional[datetime] = None

    def initiate_override(self, action: str, reason: str,
                         confirmation_callback: Optional[Callable] = None) -> tuple[bool, str]:
        """
        Initiate a human override ceremony.

        Args:
            action: Description of the action being overridden
            reason: Reason for the override
            confirmation_callback: Optional function to get confirmation (for testing)

        Returns:
            (success, message)
        """
        print("\n" + "=" * 70)
        print("HUMAN OVERRIDE CEREMONY INITIATED")
        print("=" * 70)
        print(f"Action: {action}")
        print(f"Reason: {reason}")
        print("=" * 70)

        # Log ceremony initiation
        self.daemon.event_logger.log_event(
            EventType.OVERRIDE,
            f"Override ceremony initiated: {action}",
            metadata={
                'action': action,
                'reason': reason,
                'status': 'initiated'
            }
        )

        # Step 1: Verify human presence
        print("\nStep 1/3: Verifying human presence...")
        if not self._verify_human_presence(confirmation_callback):
            self._log_ceremony_failed(action, "Human presence verification failed")
            return (False, "Human presence verification failed")

        # Step 2: Cooldown delay
        print(f"\nStep 2/3: Mandatory cooldown ({self.cooldown_seconds} seconds)...")
        print("This delay ensures deliberate action, not impulse.")
        self._cooldown_delay()

        # Step 3: Final confirmation
        print("\nStep 3/3: Final confirmation required...")
        if not self._final_confirmation(action, confirmation_callback):
            self._log_ceremony_failed(action, "Final confirmation denied")
            return (False, "Final confirmation denied")

        # Ceremony complete
        self._last_ceremony = datetime.utcnow()
        self.daemon.event_logger.log_event(
            EventType.OVERRIDE,
            f"Override ceremony completed: {action}",
            metadata={
                'action': action,
                'reason': reason,
                'status': 'completed',
                'timestamp': self._last_ceremony.isoformat() + "Z"
            }
        )

        print("\n" + "=" * 70)
        print("OVERRIDE CEREMONY COMPLETED")
        print("=" * 70 + "\n")

        return (True, "Override ceremony completed successfully")

    def _verify_human_presence(self, confirmation_callback: Optional[Callable] = None) -> bool:
        """Verify that a human is present"""
        if confirmation_callback:
            return confirmation_callback("Are you physically present? (yes/no): ")

        try:
            # Request keyboard input
            response = input("Type 'PRESENT' to confirm physical presence: ")
            return response.strip().upper() == 'PRESENT'
        except Exception:
            return False

    def _cooldown_delay(self):
        """Implement mandatory cooldown delay"""
        start_time = time.time()
        remaining = self.cooldown_seconds

        while remaining > 0:
            print(f"\rWaiting... {remaining} seconds remaining", end='', flush=True)
            time.sleep(1)
            remaining = self.cooldown_seconds - int(time.time() - start_time)

        print("\r" + " " * 50 + "\r", end='', flush=True)

    def _final_confirmation(self, action: str, confirmation_callback: Optional[Callable] = None) -> bool:
        """Get final confirmation from human"""
        if confirmation_callback:
            return confirmation_callback(f"Confirm override: {action} (yes/no): ")

        try:
            print(f"\nYou are about to override: {action}")
            print("This action will be logged in the immutable event chain.")
            response = input("\nType 'CONFIRM' to proceed: ")
            return response.strip().upper() == 'CONFIRM'
        except Exception:
            return False

    def _log_ceremony_failed(self, action: str, reason: str):
        """Log failed ceremony"""
        self.daemon.event_logger.log_event(
            EventType.OVERRIDE,
            f"Override ceremony failed: {action}",
            metadata={
                'action': action,
                'status': 'failed',
                'reason': reason
            }
        )

    def override_lockdown(self, reason: str) -> tuple[bool, str]:
        """
        Override lockdown mode (requires ceremony).

        Args:
            reason: Reason for overriding lockdown

        Returns:
            (success, message)
        """
        if not self.daemon.lockdown_manager.is_in_lockdown():
            return (False, "System is not in lockdown")

        # Initiate ceremony
        success, message = self.initiate_override(
            action="Release LOCKDOWN mode",
            reason=reason
        )

        if not success:
            return (False, message)

        # Release lockdown
        operator = "ceremony_override"
        self.daemon.lockdown_manager.release_lockdown(operator, reason)

        # Transition to RESTRICTED mode (safe default)
        from policy_engine import Operator
        self.daemon.policy_engine.transition_mode(
            BoundaryMode.RESTRICTED,
            Operator.HUMAN,
            f"Lockdown released via ceremony: {reason}"
        )

        return (True, "Lockdown released, transitioned to RESTRICTED mode")

    def force_mode_change(self, target_mode: BoundaryMode, reason: str) -> tuple[bool, str]:
        """
        Force a mode change (requires ceremony).

        Args:
            target_mode: Target boundary mode
            reason: Reason for forced change

        Returns:
            (success, message)
        """
        current_mode = self.daemon.policy_engine.get_current_mode()

        # Check if ceremony is needed
        if current_mode == BoundaryMode.LOCKDOWN:
            return (False, "Use override_lockdown() to exit LOCKDOWN mode")

        # Initiate ceremony
        success, message = self.initiate_override(
            action=f"Force mode change from {current_mode.name} to {target_mode.name}",
            reason=reason
        )

        if not success:
            return (False, message)

        # Execute mode change
        from policy_engine import Operator
        success, msg = self.daemon.policy_engine.transition_mode(
            target_mode,
            Operator.HUMAN,
            f"Forced via ceremony: {reason}"
        )

        return (success, msg)


if __name__ == '__main__':
    # Test integrations
    print("Integration interfaces defined.")
    print("\nThese interfaces must be used by:")
    print("- Memory Vault (RecallGate)")
    print("- Agent-OS (ToolGate)")
    print("- NatLangChain/Agent-OS messages (MessageGate)")
    print("- Human operators (CeremonyManager)")
    print(f"\nMessage checker available: {MESSAGE_CHECKER_AVAILABLE}")
