"""
Boundary Client for Synth-Mind

Specialized client with synth-mind specific functionality.
"""

import sys
import os

# Add shared module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'shared', 'python'))

from boundary_client import (
    BoundaryClient as BaseBoundaryClient,
    BoundaryMode,
    MemoryClass,
    BoundaryStatus,
    PolicyDecision,
    BoundaryDaemonError,
    DaemonUnavailableError,
    PolicyDeniedError,
    get_socket_path,
)

__all__ = [
    'BoundaryClient',
    'BoundaryMode',
    'MemoryClass',
    'BoundaryStatus',
    'PolicyDecision',
    'BoundaryDaemonError',
    'DaemonUnavailableError',
    'PolicyDeniedError',
]


class BoundaryClient(BaseBoundaryClient):
    """
    Synth-Mind specific boundary client.

    Adds methods specific to cognitive and reflection operations.
    """

    def check_reflection(
        self,
        reflection_type: str = 'meta',
        depth: int = 1,
        context: dict = None,
    ) -> PolicyDecision:
        """
        Check if reflection is permitted.

        Args:
            reflection_type: Type of reflection ('meta', 'introspective', 'corrective')
            depth: Reflection depth (number of nested reflections)
            context: Additional context

        Returns:
            Policy decision
        """
        # Reflection requires at least OPEN mode
        # Deeper reflections may require higher modes
        try:
            status = self.get_status()
        except BoundaryDaemonError:
            return PolicyDecision(
                permitted=False,
                reason="Boundary daemon unavailable - reflection denied",
            )

        if status.mode == BoundaryMode.LOCKDOWN:
            return PolicyDecision(
                permitted=False,
                reason="System in LOCKDOWN - all cognitive processes halted",
                mode=status.mode,
            )

        # Deep reflection requires more restrictive modes
        if depth > 3 and status.mode == BoundaryMode.OPEN:
            return PolicyDecision(
                permitted=False,
                reason="Deep reflection (depth > 3) requires RESTRICTED mode or higher",
                mode=status.mode,
            )

        # Introspective reflection of sensitive memories requires higher modes
        if reflection_type == 'introspective' and status.mode in [BoundaryMode.OPEN]:
            # Check if we're in a network-exposed environment
            if status.network_state == 'online':
                return PolicyDecision(
                    permitted=False,
                    reason="Introspective reflection on sensitive data denied in OPEN mode with network",
                    mode=status.mode,
                )

        return PolicyDecision(
            permitted=True,
            reason=f"Reflection permitted in {status.mode.value} mode",
            mode=status.mode,
        )

    def check_cognitive_process(
        self,
        process_name: str,
        requires_memory: bool = False,
        memory_class: int = 0,
        requires_network: bool = False,
    ) -> PolicyDecision:
        """
        Check if a cognitive process is permitted.

        Args:
            process_name: Name of the cognitive process
            requires_memory: Whether process needs memory access
            memory_class: Memory classification if memory is required
            requires_network: Whether process needs network

        Returns:
            Policy decision
        """
        # Check tool permission first
        decision = self.check_tool(
            tool_name=f"cognitive:{process_name}",
            requires_network=requires_network,
        )

        if not decision.permitted:
            return decision

        # Check memory permission if required
        if requires_memory:
            recall_decision = self.check_recall(memory_class=memory_class)
            if not recall_decision.permitted:
                return PolicyDecision(
                    permitted=False,
                    reason=f"Cognitive process '{process_name}' denied: {recall_decision.reason}",
                )

        return PolicyDecision(
            permitted=True,
            reason=f"Cognitive process '{process_name}' permitted",
        )

    def check_emotion_regulation(
        self,
        emotion_type: str,
        intensity: float,
    ) -> PolicyDecision:
        """
        Check if emotion regulation is permitted.

        Emotion regulation during sensitive operations may be restricted.

        Args:
            emotion_type: Type of emotion being regulated
            intensity: Emotion intensity (0.0 - 1.0)

        Returns:
            Policy decision
        """
        try:
            status = self.get_status()
        except BoundaryDaemonError:
            return PolicyDecision(
                permitted=False,
                reason="Boundary daemon unavailable - emotion regulation denied",
            )

        if status.mode == BoundaryMode.LOCKDOWN:
            return PolicyDecision(
                permitted=False,
                reason="Emotion regulation halted during LOCKDOWN",
            )

        # High-intensity emotions during COLDROOM/AIRGAP may indicate attack
        if intensity > 0.8 and status.mode in [BoundaryMode.COLDROOM, BoundaryMode.AIRGAP]:
            return PolicyDecision(
                permitted=True,
                reason="High-intensity emotion flagged for logging in secure mode",
                requires_ceremony=True,  # Log this for review
            )

        return PolicyDecision(
            permitted=True,
            reason="Emotion regulation permitted",
        )

    def report_psychological_state(
        self,
        state: dict,
    ) -> bool:
        """
        Report current psychological state to boundary daemon for monitoring.

        Args:
            state: Current psychological state metrics

        Returns:
            True if reported successfully
        """
        try:
            response = self._send_request('check_message', {
                'content': f"SYNTH_MIND_STATE:{state}",
                'source': 'synth-mind',
                'context': {'type': 'psychological_state', 'state': state},
            })
            return response.get('success', False)
        except BoundaryDaemonError:
            return False
