"""
API Module for Boundary Daemon

Provides HTTP and health check endpoints:
- Health Check API for Kubernetes/systemd probes
"""

from .health import (
    HealthCheckServer,
    HealthChecker,
    HealthCheckResult,
    ComponentHealth,
    HealthStatus,
    get_health_server,
    create_health_server,
)

__all__ = [
    'HealthCheckServer',
    'HealthChecker',
    'HealthCheckResult',
    'ComponentHealth',
    'HealthStatus',
    'get_health_server',
    'create_health_server',
]
