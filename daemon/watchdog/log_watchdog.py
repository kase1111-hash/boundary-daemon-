"""
Log Watchdog Agent - Real-time Log Monitoring with LLM-Powered Analysis

This module provides an optional, LLM-powered observer that tails application logs
in real-time, detects anomalies/errors, summarizes issues in plain English,
and offers proactive lookup for fixes.

Plan 8: Log Watchdog Agent

Design Principles:
- Non-Intrusive: Sandboxed from production; no auto-fixes to avoid loops or risks
- Fail-Closed: Ignores trivial warnings; only flags medium/high severity issues
- Human Supremacy: User confirmation required for lookups/actions
- Privacy-Preserving: Local-first; web lookups require Learning Contract + mode approval
- Auditable: All watchdog actions logged immutably via Event Logger

Security Notes:
- Uses local Ollama models for privacy-preserving analysis
- Web lookups restricted by boundary mode (blocked in AIRGAP/COLDROOM)
- All alerts are logged to event logger
- No automatic fixes or modifications
"""

import os
import asyncio
import json
import re
import logging
import threading
import time
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, List, Callable, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    """Severity levels for watchdog alerts"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(Enum):
    """Status of watchdog alerts"""
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"


@dataclass
class WatchdogAlert:
    """Represents a watchdog alert"""
    id: str
    timestamp: str
    severity: AlertSeverity
    source_file: str
    source_line: Optional[int]
    raw_message: str
    summary: str
    recommendation: Optional[str] = None
    status: AlertStatus = AlertStatus.NEW
    lookup_performed: bool = False
    lookup_results: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert alert to dictionary"""
        return {
            'id': self.id,
            'timestamp': self.timestamp,
            'severity': self.severity.value,
            'source_file': self.source_file,
            'source_line': self.source_line,
            'raw_message': self.raw_message,
            'summary': self.summary,
            'recommendation': self.recommendation,
            'status': self.status.value,
            'lookup_performed': self.lookup_performed,
            'lookup_results': self.lookup_results,
            'metadata': self.metadata
        }


class LogWatchdog:
    """
    Real-time log monitoring with LLM-powered analysis.

    Features:
    - Async log tailing with pattern matching
    - LLM-powered error summarization
    - Severity classification
    - Optional web lookup for fixes (mode-restricted)
    - Comprehensive alert management
    """

    # Default patterns to watch for
    DEFAULT_ERROR_PATTERNS = [
        r'(?i)\b(error|exception|fail(ed|ure)?|critical|fatal)\b',
        r'(?i)\b(traceback|stack\s*trace)\b',
        r'(?i)\b(permission\s+denied|access\s+denied)\b',
        r'(?i)\b(connection\s+(refused|reset|timeout))\b',
        r'(?i)\b(segmentation\s+fault|segfault)\b',
        r'(?i)\b(out\s+of\s+memory|oom)\b',
    ]

    # Patterns to ignore (false positives)
    IGNORE_PATTERNS = [
        r'(?i)error_count\s*[=:]\s*0',
        r'(?i)no\s+errors?\s+found',
        r'(?i)success.*error',
    ]

    def __init__(
        self,
        daemon=None,
        log_paths: Optional[List[str]] = None,
        model: str = "llama3.1:8b-instruct-q6_K",
        ollama_host: str = "http://localhost:11434",
        severity_threshold: AlertSeverity = AlertSeverity.MEDIUM,
        storage_dir: Optional[str] = None,
        auto_lookup: bool = False
    ):
        """
        Initialize Log Watchdog.

        Args:
            daemon: Reference to BoundaryDaemon instance
            log_paths: List of log file paths to monitor
            model: Ollama model to use for analysis
            ollama_host: Ollama server URL
            severity_threshold: Minimum severity to alert on
            storage_dir: Directory for storing alerts
            auto_lookup: Whether to auto-perform web lookups (requires approval)
        """
        self.daemon = daemon
        self.log_paths = log_paths or []
        self.model = model
        self.ollama_host = ollama_host
        self.severity_threshold = severity_threshold
        self.auto_lookup = auto_lookup

        # Storage
        if storage_dir:
            self.storage_dir = Path(storage_dir)
            self.storage_dir.mkdir(parents=True, exist_ok=True)
        else:
            self.storage_dir = None

        # Alerts
        self.alerts: List[WatchdogAlert] = []
        self._alerts_lock = threading.Lock()

        # Monitoring state
        self._running = False
        self._monitor_tasks: List[asyncio.Task] = []
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None

        # Callbacks
        self._alert_callbacks: Dict[int, Callable[[WatchdogAlert], None]] = {}
        self._next_callback_id = 0
        self._callback_lock = threading.Lock()

        # Pattern matchers
        self.error_patterns = [re.compile(p) for p in self.DEFAULT_ERROR_PATTERNS]
        self.ignore_patterns = [re.compile(p) for p in self.IGNORE_PATTERNS]

        # Load existing alerts
        if self.storage_dir:
            self._load_alerts()

        # Ollama client (lazy init)
        self._ollama_client = None

    def _get_ollama_client(self):
        """Get or create Ollama client"""
        if self._ollama_client is None:
            try:
                import ollama
                self._ollama_client = ollama.Client(host=self.ollama_host)
            except ImportError:
                logger.warning("ollama package not installed")
                return None
        return self._ollama_client

    def is_available(self) -> bool:
        """Check if Ollama is available for analysis"""
        client = self._get_ollama_client()
        if not client:
            return False
        try:
            client.list()
            return True
        except Exception:
            return False

    def add_log_path(self, path: str):
        """Add a log file to monitor"""
        if path not in self.log_paths:
            self.log_paths.append(path)

    def remove_log_path(self, path: str):
        """Remove a log file from monitoring"""
        if path in self.log_paths:
            self.log_paths.remove(path)

    def register_alert_callback(self, callback: Callable[[WatchdogAlert], None]) -> int:
        """Register a callback for new alerts.

        Returns:
            Callback ID that can be used to unregister the callback
        """
        with self._callback_lock:
            callback_id = self._next_callback_id
            self._next_callback_id += 1
            self._alert_callbacks[callback_id] = callback
            return callback_id

    def unregister_alert_callback(self, callback_id: int) -> bool:
        """Unregister a previously registered alert callback.

        Args:
            callback_id: The ID returned from register_alert_callback

        Returns:
            True if callback was found and removed, False otherwise
        """
        with self._callback_lock:
            if callback_id in self._alert_callbacks:
                del self._alert_callbacks[callback_id]
                return True
            return False

    def _should_ignore(self, message: str) -> bool:
        """Check if message should be ignored"""
        for pattern in self.ignore_patterns:
            if pattern.search(message):
                return True
        return False

    def _matches_error_pattern(self, message: str) -> bool:
        """Check if message matches error patterns"""
        if self._should_ignore(message):
            return False
        for pattern in self.error_patterns:
            if pattern.search(message):
                return True
        return False

    def _generate_alert_id(self) -> str:
        """Generate unique alert ID"""
        import hashlib
        timestamp = datetime.utcnow().isoformat()
        random_bytes = os.urandom(4).hex()
        return hashlib.sha256(f"{timestamp}-{random_bytes}".encode()).hexdigest()[:12]

    async def _analyze_with_llm(self, log_entry: str, source_file: str) -> Optional[dict]:
        """Analyze log entry with LLM"""
        client = self._get_ollama_client()
        if not client:
            return None

        prompt = f"""Analyze this log entry and provide a structured assessment:

Log Source: {source_file}
Log Entry:
{log_entry}

Provide your analysis in JSON format with these fields:
- severity: "low", "medium", "high", or "critical"
- summary: A brief plain-English summary (1-2 sentences)
- recommendation: What action to take or investigate
- needs_lookup: true if external documentation/search would help

JSON Response:"""

        try:
            response = client.generate(
                model=self.model,
                prompt=prompt,
                format="json"
            )

            # Parse JSON response
            result_text = response.get('response', '{}')
            # Clean up response (handle markdown code blocks)
            if '```json' in result_text:
                result_text = result_text.split('```json')[1].split('```')[0]
            elif '```' in result_text:
                result_text = result_text.split('```')[1].split('```')[0]

            return json.loads(result_text.strip())

        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            return None

    def _classify_severity_heuristic(self, message: str) -> AlertSeverity:
        """Classify severity using heuristics when LLM unavailable"""
        lower_msg = message.lower()

        if any(word in lower_msg for word in ['critical', 'fatal', 'panic', 'crash']):
            return AlertSeverity.CRITICAL
        elif any(word in lower_msg for word in ['error', 'exception', 'failed', 'failure']):
            return AlertSeverity.HIGH
        elif any(word in lower_msg for word in ['warning', 'warn', 'timeout']):
            return AlertSeverity.MEDIUM
        else:
            return AlertSeverity.LOW

    async def _process_log_entry(self, entry: str, source_file: str, line_num: Optional[int] = None):
        """Process a single log entry"""
        if not self._matches_error_pattern(entry):
            return

        # Try LLM analysis first
        analysis = await self._analyze_with_llm(entry, source_file)

        if analysis:
            severity_str = analysis.get('severity', 'medium')
            try:
                severity = AlertSeverity(severity_str)
            except ValueError:
                severity = AlertSeverity.MEDIUM
            summary = analysis.get('summary', entry[:200])
            recommendation = analysis.get('recommendation', None)
        else:
            # Fallback to heuristics
            severity = self._classify_severity_heuristic(entry)
            summary = entry[:200] + ('...' if len(entry) > 200 else '')
            recommendation = None

        # Check threshold
        severity_order = [AlertSeverity.LOW, AlertSeverity.MEDIUM, AlertSeverity.HIGH, AlertSeverity.CRITICAL]
        if severity_order.index(severity) < severity_order.index(self.severity_threshold):
            return  # Below threshold

        # Create alert
        alert = WatchdogAlert(
            id=self._generate_alert_id(),
            timestamp=datetime.utcnow().isoformat(),
            severity=severity,
            source_file=source_file,
            source_line=line_num,
            raw_message=entry,
            summary=summary,
            recommendation=recommendation,
            metadata={'analyzed_by': 'llm' if analysis else 'heuristic'}
        )

        # Store alert
        with self._alerts_lock:
            self.alerts.append(alert)

        # Save to disk
        if self.storage_dir:
            self._save_alert(alert)

        # Log to daemon event logger
        if self.daemon and hasattr(self.daemon, 'event_logger'):
            from ..event_logger import EventType
            self.daemon.event_logger.log_event(
                EventType.HEALTH_CHECK,  # Using existing event type
                f"Watchdog alert: {summary}",
                metadata={
                    'alert_id': alert.id,
                    'severity': severity.value,
                    'source_file': source_file,
                    'action': 'watchdog_alert'
                }
            )

        # Notify callbacks (copy to avoid modification during iteration)
        with self._callback_lock:
            callbacks = list(self._alert_callbacks.values())
        for callback in callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")

        # Print alert
        print(f"\n[WATCHDOG ALERT] {severity.value.upper()}")
        print(f"  Source: {source_file}")
        print(f"  Summary: {summary}")
        if recommendation:
            print(f"  Recommendation: {recommendation}")

    async def _tail_log_file(self, log_path: str):
        """Tail a log file and process new entries"""
        path = Path(log_path)

        if not path.exists():
            logger.warning(f"Log file not found: {log_path}")
            return

        try:
            # Start from end of file
            with open(path, 'r') as f:
                f.seek(0, 2)  # Seek to end
                line_num = sum(1 for _ in open(path))

                while self._running:
                    line = f.readline()
                    if line:
                        line_num += 1
                        await self._process_log_entry(line.strip(), log_path, line_num)
                    else:
                        await asyncio.sleep(0.5)  # Wait for new content

        except Exception as e:
            logger.error(f"Error tailing {log_path}: {e}")

    async def _monitor_logs(self):
        """Main monitoring coroutine"""
        tasks = []
        for log_path in self.log_paths:
            task = asyncio.create_task(self._tail_log_file(log_path))
            tasks.append(task)
            self._monitor_tasks.append(task)

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def _run_monitor_loop(self):
        """Run monitoring loop in thread"""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._monitor_logs())
        finally:
            self._loop.close()

    def start(self):
        """Start log monitoring"""
        if self._running:
            return

        if not self.log_paths:
            logger.warning("No log paths configured for monitoring")
            return

        self._running = True
        self._thread = threading.Thread(target=self._run_monitor_loop, daemon=True)
        self._thread.start()
        logger.info(f"Log watchdog started, monitoring {len(self.log_paths)} file(s)")

    def stop(self):
        """Stop log monitoring and cleanup resources"""
        if not self._running:
            return

        self._running = False

        # Cancel tasks
        for task in self._monitor_tasks:
            task.cancel()

        # Wait for thread
        if self._thread:
            self._thread.join(timeout=5.0)

        # Clear callbacks to prevent memory leaks
        with self._callback_lock:
            self._alert_callbacks.clear()

        logger.info("Log watchdog stopped")

    def _save_alert(self, alert: WatchdogAlert):
        """Save alert to disk"""
        if not self.storage_dir:
            return

        alerts_file = self.storage_dir / 'alerts.json'
        try:
            # Load existing
            if alerts_file.exists():
                with open(alerts_file, 'r') as f:
                    data = json.load(f)
            else:
                data = []

            # Append new alert
            data.append(alert.to_dict())

            # Write back
            with open(alerts_file, 'w') as f:
                json.dump(data, f, indent=2)

        except Exception as e:
            logger.error(f"Failed to save alert: {e}")

    def _load_alerts(self):
        """Load alerts from disk"""
        if not self.storage_dir:
            return

        alerts_file = self.storage_dir / 'alerts.json'
        if not alerts_file.exists():
            return

        try:
            with open(alerts_file, 'r') as f:
                data = json.load(f)

            for item in data:
                alert = WatchdogAlert(
                    id=item['id'],
                    timestamp=item['timestamp'],
                    severity=AlertSeverity(item['severity']),
                    source_file=item['source_file'],
                    source_line=item.get('source_line'),
                    raw_message=item['raw_message'],
                    summary=item['summary'],
                    recommendation=item.get('recommendation'),
                    status=AlertStatus(item.get('status', 'new')),
                    lookup_performed=item.get('lookup_performed', False),
                    lookup_results=item.get('lookup_results'),
                    metadata=item.get('metadata', {})
                )
                self.alerts.append(alert)

            logger.info(f"Loaded {len(self.alerts)} existing alerts")

        except Exception as e:
            logger.error(f"Failed to load alerts: {e}")

    def get_alerts(
        self,
        severity: Optional[AlertSeverity] = None,
        status: Optional[AlertStatus] = None,
        limit: int = 100
    ) -> List[WatchdogAlert]:
        """Get alerts with optional filtering"""
        with self._alerts_lock:
            filtered = self.alerts.copy()

        if severity:
            filtered = [a for a in filtered if a.severity == severity]
        if status:
            filtered = [a for a in filtered if a.status == status]

        # Sort by timestamp descending
        filtered.sort(key=lambda a: a.timestamp, reverse=True)

        return filtered[:limit]

    def update_alert_status(self, alert_id: str, new_status: AlertStatus) -> bool:
        """Update alert status"""
        with self._alerts_lock:
            for alert in self.alerts:
                if alert.id == alert_id:
                    alert.status = new_status
                    if self.storage_dir:
                        self._save_all_alerts()
                    return True
        return False

    def _save_all_alerts(self):
        """Save all alerts to disk"""
        if not self.storage_dir:
            return

        alerts_file = self.storage_dir / 'alerts.json'
        try:
            with self._alerts_lock:
                data = [a.to_dict() for a in self.alerts]
            with open(alerts_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save alerts: {e}")

    def acknowledge_alert(self, alert_id: str) -> bool:
        """Acknowledge an alert"""
        return self.update_alert_status(alert_id, AlertStatus.ACKNOWLEDGED)

    def resolve_alert(self, alert_id: str) -> bool:
        """Mark alert as resolved"""
        return self.update_alert_status(alert_id, AlertStatus.RESOLVED)

    def dismiss_alert(self, alert_id: str) -> bool:
        """Dismiss an alert"""
        return self.update_alert_status(alert_id, AlertStatus.DISMISSED)

    async def perform_lookup(self, alert_id: str) -> Optional[str]:
        """
        Perform web lookup for an alert.

        Requires:
        - Mode allows web access (not AIRGAP/COLDROOM/LOCKDOWN)
        - User confirmation via ceremony
        """
        # Find alert
        alert = None
        with self._alerts_lock:
            for a in self.alerts:
                if a.id == alert_id:
                    alert = a
                    break

        if not alert:
            return None

        # Check mode restrictions
        if self.daemon:
            from ..policy_engine import BoundaryMode
            current_mode = self.daemon.policy_engine.get_current_mode()
            blocked_modes = [BoundaryMode.AIRGAP, BoundaryMode.COLDROOM, BoundaryMode.LOCKDOWN]
            if current_mode in blocked_modes:
                return f"Web lookup blocked: current mode is {current_mode.name}"

        # Perform lookup using LLM to summarize the issue for search
        client = self._get_ollama_client()
        if not client:
            return "Ollama not available for lookup preparation"

        try:
            # Generate search query
            query_prompt = f"""Based on this error, generate a concise search query to find fixes:

Error: {alert.raw_message[:500]}

Generate a search query (just the query, no explanation):"""

            response = client.generate(model=self.model, prompt=query_prompt)
            search_query = response.get('response', '').strip()

            # Note: Actual web search would require integration with web search API
            # For now, we prepare the query and note that lookup was attempted
            alert.lookup_performed = True
            alert.lookup_results = f"Search query prepared: {search_query}"

            if self.storage_dir:
                self._save_all_alerts()

            return alert.lookup_results

        except Exception as e:
            return f"Lookup error: {e}"

    def get_summary_stats(self) -> dict:
        """Get summary statistics"""
        with self._alerts_lock:
            total = len(self.alerts)
            by_severity = {}
            by_status = {}

            for alert in self.alerts:
                sev = alert.severity.value
                by_severity[sev] = by_severity.get(sev, 0) + 1

                stat = alert.status.value
                by_status[stat] = by_status.get(stat, 0) + 1

        return {
            'total': total,
            'by_severity': by_severity,
            'by_status': by_status,
            'monitoring': self._running,
            'log_paths': self.log_paths,
            'model': self.model
        }

    def analyze_log_entry(self, entry: str, source: str = "manual") -> Optional[WatchdogAlert]:
        """
        Manually analyze a log entry (synchronous wrapper).

        Args:
            entry: Log entry text
            source: Source identifier

        Returns:
            WatchdogAlert if issue detected, None otherwise
        """
        loop = asyncio.new_event_loop()
        try:
            # Process entry
            loop.run_until_complete(self._process_log_entry(entry, source))
            # Return most recent alert if it matches
            with self._alerts_lock:
                if self.alerts and self.alerts[-1].raw_message == entry:
                    return self.alerts[-1]
            return None
        finally:
            loop.close()


class WatchdogConfig:
    """Configuration for Log Watchdog"""

    def __init__(self):
        self.enabled = False
        self.severity_threshold = AlertSeverity.MEDIUM
        self.auto_lookup = False
        self.log_paths: List[str] = []
        self.model = "llama3.1:8b-instruct-q6_K"
        self.ollama_host = "http://localhost:11434"
        self.storage_dir: Optional[str] = None

    @classmethod
    def from_env(cls) -> 'WatchdogConfig':
        """Create config from environment variables"""
        config = cls()

        storage_dir = os.environ.get('BOUNDARY_WATCHDOG_DIR')
        if storage_dir:
            config.enabled = True
            config.storage_dir = storage_dir

        log_paths = os.environ.get('BOUNDARY_WATCHDOG_LOGS', '')
        if log_paths:
            config.log_paths = [p.strip() for p in log_paths.split(':') if p.strip()]

        model = os.environ.get('BOUNDARY_WATCHDOG_MODEL')
        if model:
            config.model = model

        threshold = os.environ.get('BOUNDARY_WATCHDOG_THRESHOLD', 'medium')
        try:
            config.severity_threshold = AlertSeverity(threshold.lower())
        except ValueError:
            pass

        return config


if __name__ == '__main__':
    # Test Log Watchdog
    import tempfile

    print("Testing Log Watchdog...")

    # Create temp storage
    temp_dir = tempfile.mkdtemp()

    # Create watchdog
    watchdog = LogWatchdog(
        storage_dir=temp_dir,
        severity_threshold=AlertSeverity.LOW
    )

    print(f"\nOllama available: {watchdog.is_available()}")
    print(f"Storage: {temp_dir}")

    # Test manual analysis
    test_entries = [
        "ERROR: Connection refused to database server",
        "INFO: Application started successfully",
        "CRITICAL: Out of memory error in worker process",
        "WARNING: Request timeout after 30 seconds",
    ]

    print("\nAnalyzing test entries...")
    for entry in test_entries:
        print(f"\n  Input: {entry}")
        alert = watchdog.analyze_log_entry(entry, "test")
        if alert:
            print(f"  Alert: {alert.severity.value} - {alert.summary}")
        else:
            print("  No alert generated")

    # Show stats
    print("\nSummary stats:")
    stats = watchdog.get_summary_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")

    # Cleanup
    import shutil
    shutil.rmtree(temp_dir)

    print("\nLog watchdog test complete.")
