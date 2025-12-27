"""
Monitoring Report Generator

Generates comprehensive monitoring reports and uses Ollama for interpretation.

Features:
- Collects data from all monitoring systems
- Generates structured JSON reports
- Sends to Ollama for AI-powered interpretation
- Supports configurable Ollama models and endpoints
"""

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, Optional, List, TYPE_CHECKING
from enum import Enum
import urllib.request
import urllib.error

if TYPE_CHECKING:
    from .boundary_daemon import BoundaryDaemon

logger = logging.getLogger(__name__)


class ReportType(Enum):
    """Types of monitoring reports"""
    FULL = "full"           # All monitoring data
    SUMMARY = "summary"     # Key metrics only
    ALERTS = "alerts"       # Recent alerts only
    HEALTH = "health"       # Health-focused report


@dataclass
class OllamaConfig:
    """Configuration for Ollama integration"""
    endpoint: str = "http://localhost:11434"
    model: str = "llama3.2"
    timeout: int = 60
    temperature: float = 0.3
    max_tokens: int = 2048
    system_prompt: str = """You are a system monitoring analyst. Analyze the provided monitoring data and:
1. Identify any critical issues or anomalies
2. Highlight concerning trends (memory leaks, CPU spikes, connection issues)
3. Provide actionable recommendations
4. Summarize overall system health

Be concise and focus on actionable insights. Use bullet points for clarity."""


@dataclass
class MonitoringReport:
    """A monitoring report with raw data and optional interpretation"""
    timestamp: float
    report_type: ReportType
    raw_data: Dict[str, Any]
    interpretation: Optional[str] = None
    ollama_model: Optional[str] = None
    generation_time_ms: float = 0.0
    interpretation_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'timestamp_iso': datetime.fromtimestamp(self.timestamp).isoformat(),
            'report_type': self.report_type.value,
            'raw_data': self.raw_data,
            'interpretation': self.interpretation,
            'ollama_model': self.ollama_model,
            'generation_time_ms': self.generation_time_ms,
            'interpretation_time_ms': self.interpretation_time_ms,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)


class OllamaClient:
    """Simple client for Ollama API"""

    def __init__(self, config: Optional[OllamaConfig] = None):
        self.config = config or OllamaConfig()

    def is_available(self) -> bool:
        """Check if Ollama is running and accessible"""
        try:
            url = f"{self.config.endpoint}/api/tags"
            req = urllib.request.Request(url, method='GET')
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status == 200
        except Exception:
            return False

    def list_models(self) -> List[str]:
        """List available models"""
        try:
            url = f"{self.config.endpoint}/api/tags"
            req = urllib.request.Request(url, method='GET')
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode('utf-8'))
                return [m['name'] for m in data.get('models', [])]
        except Exception as e:
            logger.error(f"Failed to list Ollama models: {e}")
            return []

    def generate(self, prompt: str, system: Optional[str] = None) -> Optional[str]:
        """Generate a response from Ollama"""
        try:
            url = f"{self.config.endpoint}/api/generate"

            payload = {
                'model': self.config.model,
                'prompt': prompt,
                'stream': False,
                'options': {
                    'temperature': self.config.temperature,
                    'num_predict': self.config.max_tokens,
                }
            }

            if system:
                payload['system'] = system

            data = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(
                url,
                data=data,
                headers={'Content-Type': 'application/json'},
                method='POST'
            )

            with urllib.request.urlopen(req, timeout=self.config.timeout) as response:
                result = json.loads(response.read().decode('utf-8'))
                return result.get('response')

        except urllib.error.URLError as e:
            logger.error(f"Ollama connection error: {e}")
            return None
        except Exception as e:
            logger.error(f"Ollama generation error: {e}")
            return None


class MonitoringReportGenerator:
    """Generates monitoring reports with Ollama interpretation"""

    def __init__(
        self,
        daemon: Optional['BoundaryDaemon'] = None,
        ollama_config: Optional[OllamaConfig] = None,
    ):
        self.daemon = daemon
        self.ollama_config = ollama_config or OllamaConfig()
        self.ollama_client = OllamaClient(self.ollama_config)
        self._report_history: List[MonitoringReport] = []
        self._max_history = 100

    def set_daemon(self, daemon: 'BoundaryDaemon'):
        """Set the daemon reference"""
        self.daemon = daemon

    def set_ollama_config(self, config: OllamaConfig):
        """Update Ollama configuration"""
        self.ollama_config = config
        self.ollama_client = OllamaClient(config)

    def check_ollama_status(self) -> Dict[str, Any]:
        """Check Ollama availability and list models"""
        available = self.ollama_client.is_available()
        models = self.ollama_client.list_models() if available else []
        return {
            'available': available,
            'endpoint': self.ollama_config.endpoint,
            'configured_model': self.ollama_config.model,
            'available_models': models,
            'model_available': self.ollama_config.model in models if models else False,
        }

    def _collect_memory_data(self) -> Dict[str, Any]:
        """Collect memory monitoring data"""
        if not self.daemon:
            return {'error': 'No daemon reference'}

        if not hasattr(self.daemon, 'memory_monitor') or not self.daemon.memory_monitor:
            return {'available': False}

        if not getattr(self.daemon, 'memory_monitor_enabled', False):
            return {'enabled': False}

        try:
            return {
                'enabled': True,
                'stats': self.daemon.memory_monitor.get_stats(),
            }
        except Exception as e:
            return {'enabled': True, 'error': str(e)}

    def _collect_resource_data(self) -> Dict[str, Any]:
        """Collect resource monitoring data"""
        if not self.daemon:
            return {'error': 'No daemon reference'}

        if not hasattr(self.daemon, 'resource_monitor') or not self.daemon.resource_monitor:
            return {'available': False}

        if not getattr(self.daemon, 'resource_monitor_enabled', False):
            return {'enabled': False}

        try:
            data = {'enabled': True}

            if hasattr(self.daemon.resource_monitor, 'get_cpu_stats'):
                data['cpu'] = self.daemon.resource_monitor.get_cpu_stats()

            if hasattr(self.daemon.resource_monitor, 'get_connection_stats'):
                data['connections'] = self.daemon.resource_monitor.get_connection_stats()

            if hasattr(self.daemon.resource_monitor, 'get_current_snapshot'):
                snapshot = self.daemon.resource_monitor.get_current_snapshot()
                if snapshot:
                    data['current'] = {
                        'fd_count': snapshot.fd_count,
                        'thread_count': snapshot.thread_count,
                        'disk_used_percent': snapshot.disk_used_percent,
                        'cpu_percent': snapshot.cpu_percent,
                        'connection_count': snapshot.connection_count,
                    }

            return data
        except Exception as e:
            return {'enabled': True, 'error': str(e)}

    def _collect_health_data(self) -> Dict[str, Any]:
        """Collect health monitoring data"""
        if not self.daemon:
            return {'error': 'No daemon reference'}

        if not hasattr(self.daemon, 'health_monitor') or not self.daemon.health_monitor:
            return {'available': False}

        if not getattr(self.daemon, 'health_monitor_enabled', False):
            return {'enabled': False}

        try:
            return {
                'enabled': True,
                'summary': self.daemon.health_monitor.get_summary(),
            }
        except Exception as e:
            return {'enabled': True, 'error': str(e)}

    def _collect_queue_data(self) -> Dict[str, Any]:
        """Collect queue monitoring data"""
        if not self.daemon:
            return {'error': 'No daemon reference'}

        if not hasattr(self.daemon, 'queue_monitor') or not self.daemon.queue_monitor:
            return {'available': False}

        if not getattr(self.daemon, 'queue_monitor_enabled', False):
            return {'enabled': False}

        try:
            return {
                'enabled': True,
                'summary': self.daemon.queue_monitor.get_summary(),
            }
        except Exception as e:
            return {'enabled': True, 'error': str(e)}

    def _collect_alerts(self) -> List[Dict[str, Any]]:
        """Collect recent alerts from all monitors"""
        alerts = []

        if not self.daemon:
            return alerts

        # Get alerts from event logger
        if hasattr(self.daemon, 'event_logger'):
            try:
                from .event_logger import EventType
                recent_alerts = self.daemon.event_logger.get_events_by_type(
                    EventType.ALERT, limit=50
                )
                for alert in recent_alerts:
                    alerts.append(alert.to_dict())
            except Exception as e:
                logger.warning(f"Failed to collect alerts from event logger: {e}")

        return alerts

    def _collect_daemon_status(self) -> Dict[str, Any]:
        """Collect basic daemon status"""
        if not self.daemon:
            return {'error': 'No daemon reference'}

        try:
            return {
                'running': getattr(self.daemon, '_running', False),
                'mode': self.daemon.policy_engine.get_current_mode().name
                        if hasattr(self.daemon, 'policy_engine') else 'unknown',
            }
        except Exception as e:
            return {'error': str(e)}

    def generate_raw_report(
        self,
        report_type: ReportType = ReportType.FULL,
    ) -> Dict[str, Any]:
        """Generate raw monitoring report data"""
        start_time = time.monotonic()

        report_data = {
            'generated_at': datetime.now().isoformat(),
            'report_type': report_type.value,
            'daemon': self._collect_daemon_status(),
        }

        if report_type == ReportType.FULL:
            report_data['memory'] = self._collect_memory_data()
            report_data['resources'] = self._collect_resource_data()
            report_data['health'] = self._collect_health_data()
            report_data['queues'] = self._collect_queue_data()
            report_data['recent_alerts'] = self._collect_alerts()

        elif report_type == ReportType.SUMMARY:
            # Collect just key metrics
            memory = self._collect_memory_data()
            resources = self._collect_resource_data()
            health = self._collect_health_data()

            report_data['summary'] = {
                'memory_mb': memory.get('stats', {}).get('current_mb', 'N/A')
                            if memory.get('enabled') else 'disabled',
                'cpu_percent': resources.get('current', {}).get('cpu_percent', 'N/A')
                              if resources.get('enabled') else 'disabled',
                'health_status': health.get('summary', {}).get('status', 'N/A')
                                if health.get('enabled') else 'disabled',
                'fd_count': resources.get('current', {}).get('fd_count', 'N/A')
                           if resources.get('enabled') else 'disabled',
            }

        elif report_type == ReportType.ALERTS:
            report_data['alerts'] = self._collect_alerts()

        elif report_type == ReportType.HEALTH:
            report_data['health'] = self._collect_health_data()
            report_data['daemon'] = self._collect_daemon_status()

        elapsed_ms = (time.monotonic() - start_time) * 1000
        report_data['generation_time_ms'] = elapsed_ms

        return report_data

    def generate_report(
        self,
        report_type: ReportType = ReportType.FULL,
        interpret: bool = True,
        custom_prompt: Optional[str] = None,
    ) -> MonitoringReport:
        """
        Generate a monitoring report with optional Ollama interpretation.

        Args:
            report_type: Type of report to generate
            interpret: Whether to send to Ollama for interpretation
            custom_prompt: Custom prompt for Ollama (overrides default)

        Returns:
            MonitoringReport with raw data and optional interpretation
        """
        gen_start = time.monotonic()

        # Generate raw report
        raw_data = self.generate_raw_report(report_type)
        gen_time = (time.monotonic() - gen_start) * 1000

        report = MonitoringReport(
            timestamp=time.time(),
            report_type=report_type,
            raw_data=raw_data,
            generation_time_ms=gen_time,
        )

        # Get interpretation from Ollama if requested
        if interpret:
            interp_start = time.monotonic()

            # Format the raw data as a prompt
            raw_json = json.dumps(raw_data, indent=2, default=str)
            prompt = custom_prompt or f"""Analyze this system monitoring report:

```json
{raw_json}
```

Provide a concise analysis focusing on:
- Any critical issues or warnings
- Resource utilization trends
- Health status assessment
- Recommended actions if needed"""

            interpretation = self.ollama_client.generate(
                prompt=prompt,
                system=self.ollama_config.system_prompt,
            )

            report.interpretation = interpretation
            report.ollama_model = self.ollama_config.model
            report.interpretation_time_ms = (time.monotonic() - interp_start) * 1000

        # Store in history
        self._report_history.append(report)
        if len(self._report_history) > self._max_history:
            self._report_history.pop(0)

        return report

    def get_report_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent report history"""
        reports = self._report_history[-limit:]
        return [r.to_dict() for r in reversed(reports)]


def create_report_generator(
    daemon: Optional['BoundaryDaemon'] = None,
    ollama_endpoint: str = "http://localhost:11434",
    ollama_model: str = "llama3.2",
) -> MonitoringReportGenerator:
    """Factory function to create a report generator"""
    config = OllamaConfig(
        endpoint=ollama_endpoint,
        model=ollama_model,
    )
    return MonitoringReportGenerator(daemon=daemon, ollama_config=config)
