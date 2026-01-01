"""
Intelligence module for Boundary Daemon.

Phase 3 Cutting-Edge Innovation: Predictive security intelligence
using deterministic rule-based analysis (not ML black box).
"""

from .mode_advisor import (
    ModeAdvisor,
    ModeRecommendation,
    ContextFactor,
    ThreatIndicator,
    RecommendationConfidence,
)

__all__ = [
    'ModeAdvisor',
    'ModeRecommendation',
    'ContextFactor',
    'ThreatIndicator',
    'RecommendationConfidence',
]
