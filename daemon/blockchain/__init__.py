"""
Boundary Daemon - Blockchain Security Module

Provides comprehensive protection for blockchain server infrastructure:
- Validator key protection with double-sign/slashing prevention
- RPC endpoint hardening and authentication
- MEV attack detection and mitigation
- Consensus safety monitoring

CRITICAL: These modules protect high-value validator infrastructure.
Proper configuration is essential to prevent financial losses from slashing.
"""

from .validator_protection import (
    ValidatorKeyProtector,
    SigningRequest,
    SigningResponse,
    SigningRecord,
    ChainType,
    SigningEventType,
    SlashingRisk,
    create_validator_protector,
)

from .rpc_protection import (
    RPCFirewall,
    RPCRequest,
    RPCResponse,
    RPCMethodPolicy,
    RPCRiskLevel,
    AuthLevel,
    MEVProtector,
    create_rpc_firewall,
)

__all__ = [
    # Validator protection
    'ValidatorKeyProtector',
    'SigningRequest',
    'SigningResponse',
    'SigningRecord',
    'ChainType',
    'SigningEventType',
    'SlashingRisk',
    'create_validator_protector',
    # RPC protection
    'RPCFirewall',
    'RPCRequest',
    'RPCResponse',
    'RPCMethodPolicy',
    'RPCRiskLevel',
    'AuthLevel',
    'MEVProtector',
    'create_rpc_firewall',
]
