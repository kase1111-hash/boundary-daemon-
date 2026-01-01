"""
Federation module for Boundary Daemon.

Phase 3 Cutting-Edge Innovation: Cross-organization threat intelligence
sharing for AI/LLM attacks with privacy-preserving mechanisms.
"""

from .threat_mesh import (
    ThreatMesh,
    ThreatSignature,
    MeshPeer,
    ThreatCategory,
    SharePolicy,
)

__all__ = [
    'ThreatMesh',
    'ThreatSignature',
    'MeshPeer',
    'ThreatCategory',
    'SharePolicy',
]
