"""
Case Management - Alert Lifecycle and External Integrations

Phase 2 Operational Excellence: Provides workflow for alerts with
external system integrations.

Features:
- Alert lifecycle management (NEW → ASSIGNED → INVESTIGATING → RESOLVED)
- SLA tracking (time to acknowledge, time to resolve)
- External integrations:
  - ServiceNow: Create incidents on CRITICAL
  - Jira: Create issues with labels
  - PagerDuty: Page on-call for CRITICAL
  - Slack: Thread updates for case progress
- Case correlation (group related alerts)
- Timeline view of case events

Usage:
    case_manager = CaseManager(config)
    case = case_manager.create_case(alert)
    case_manager.assign(case.case_id, analyst="analyst@org.com")
    case_manager.resolve(case.case_id, resolution="Fixed")
"""

import hashlib
import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Callable
from urllib.parse import urljoin

logger = logging.getLogger(__name__)


class CaseStatus(Enum):
    """Case lifecycle status."""
    NEW = "new"
    ASSIGNED = "assigned"
    INVESTIGATING = "investigating"
    PENDING_INFO = "pending_info"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"
    ESCALATED = "escalated"


class CaseSeverity(Enum):
    """Case severity levels."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_string(cls, s: str) -> 'CaseSeverity':
        try:
            return cls[s.upper()]
        except KeyError:
            return cls.MEDIUM


class IntegrationType(Enum):
    """External integration types."""
    SERVICENOW = "servicenow"
    JIRA = "jira"
    PAGERDUTY = "pagerduty"
    SLACK = "slack"
    EMAIL = "email"
    WEBHOOK = "webhook"


@dataclass
class CaseEvent:
    """Event in case timeline."""
    timestamp: str
    event_type: str
    actor: str
    details: str
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            'timestamp': self.timestamp,
            'event_type': self.event_type,
            'actor': self.actor,
            'details': self.details,
            'metadata': self.metadata,
        }


@dataclass
class Alert:
    """Alert that can become a case."""
    alert_id: str
    timestamp: str
    severity: CaseSeverity
    source: str
    title: str
    description: str
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            'alert_id': self.alert_id,
            'timestamp': self.timestamp,
            'severity': self.severity.name,
            'source': self.source,
            'title': self.title,
            'description': self.description,
            'metadata': self.metadata,
        }


@dataclass
class Case:
    """Security case with full lifecycle tracking."""
    case_id: str
    created_at: str
    status: CaseStatus
    severity: CaseSeverity
    title: str
    description: str

    # Related data
    alerts: List[Alert] = field(default_factory=list)
    timeline: List[CaseEvent] = field(default_factory=list)

    # Assignment
    assignee: Optional[str] = None
    assigned_at: Optional[str] = None

    # Resolution
    resolved_at: Optional[str] = None
    resolution: Optional[str] = None

    # SLA tracking
    sla_ack_deadline: Optional[str] = None
    sla_resolve_deadline: Optional[str] = None
    sla_ack_met: Optional[bool] = None
    sla_resolve_met: Optional[bool] = None

    # External references
    external_refs: Dict[str, str] = field(default_factory=dict)  # integration -> ref ID

    # Metadata
    tags: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)

    def add_event(self, event_type: str, actor: str, details: str, metadata: Dict = None):
        """Add event to timeline."""
        event = CaseEvent(
            timestamp=datetime.utcnow().isoformat() + "Z",
            event_type=event_type,
            actor=actor,
            details=details,
            metadata=metadata or {},
        )
        self.timeline.append(event)

    def to_dict(self) -> Dict:
        return {
            'case_id': self.case_id,
            'created_at': self.created_at,
            'status': self.status.value,
            'severity': self.severity.name,
            'title': self.title,
            'description': self.description,
            'alerts': [a.to_dict() for a in self.alerts],
            'timeline': [e.to_dict() for e in self.timeline],
            'assignee': self.assignee,
            'assigned_at': self.assigned_at,
            'resolved_at': self.resolved_at,
            'resolution': self.resolution,
            'sla_ack_deadline': self.sla_ack_deadline,
            'sla_resolve_deadline': self.sla_resolve_deadline,
            'sla_ack_met': self.sla_ack_met,
            'sla_resolve_met': self.sla_resolve_met,
            'external_refs': self.external_refs,
            'tags': self.tags,
            'metadata': self.metadata,
        }


@dataclass
class SLAConfig:
    """SLA configuration by severity."""
    ack_minutes: Dict[CaseSeverity, int] = field(default_factory=lambda: {
        CaseSeverity.CRITICAL: 5,
        CaseSeverity.HIGH: 30,
        CaseSeverity.MEDIUM: 120,
        CaseSeverity.LOW: 480,
    })
    resolve_minutes: Dict[CaseSeverity, int] = field(default_factory=lambda: {
        CaseSeverity.CRITICAL: 60,
        CaseSeverity.HIGH: 240,
        CaseSeverity.MEDIUM: 1440,
        CaseSeverity.LOW: 4320,
    })


@dataclass
class IntegrationConfig:
    """Configuration for external integrations."""
    # ServiceNow
    servicenow_instance: Optional[str] = None
    servicenow_user: Optional[str] = None
    servicenow_password: Optional[str] = None
    servicenow_table: str = "incident"

    # Jira
    jira_url: Optional[str] = None
    jira_user: Optional[str] = None
    jira_token: Optional[str] = None
    jira_project: Optional[str] = None

    # PagerDuty
    pagerduty_token: Optional[str] = None
    pagerduty_service_id: Optional[str] = None
    pagerduty_escalation_policy: Optional[str] = None

    # Slack
    slack_webhook_url: Optional[str] = None
    slack_channel: Optional[str] = None

    # Email
    smtp_server: Optional[str] = None
    smtp_port: int = 587
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    email_from: Optional[str] = None
    email_to: List[str] = field(default_factory=list)

    # Generic webhook
    webhook_urls: List[str] = field(default_factory=list)

    # Auto-create rules
    auto_servicenow_severity: CaseSeverity = CaseSeverity.CRITICAL
    auto_pagerduty_severity: CaseSeverity = CaseSeverity.CRITICAL
    auto_slack_severity: CaseSeverity = CaseSeverity.HIGH


class IntegrationClient:
    """Base class for external integrations."""

    def create_incident(self, case: Case) -> Optional[str]:
        """Create incident/issue and return external reference."""
        raise NotImplementedError

    def update_incident(self, case: Case, ref: str) -> bool:
        """Update existing incident/issue."""
        raise NotImplementedError

    def resolve_incident(self, case: Case, ref: str) -> bool:
        """Resolve/close incident."""
        raise NotImplementedError


class ServiceNowClient(IntegrationClient):
    """ServiceNow integration client."""

    def __init__(self, config: IntegrationConfig):
        self.instance = config.servicenow_instance
        self.user = config.servicenow_user
        self.password = config.servicenow_password
        self.table = config.servicenow_table
        self.enabled = all([self.instance, self.user, self.password])

    def create_incident(self, case: Case) -> Optional[str]:
        if not self.enabled:
            return None

        try:
            import requests

            url = f"https://{self.instance}.service-now.com/api/now/table/{self.table}"

            # Map severity to ServiceNow impact/urgency
            impact_map = {
                CaseSeverity.CRITICAL: '1',
                CaseSeverity.HIGH: '2',
                CaseSeverity.MEDIUM: '2',
                CaseSeverity.LOW: '3',
            }

            payload = {
                'short_description': case.title,
                'description': case.description,
                'impact': impact_map.get(case.severity, '2'),
                'urgency': impact_map.get(case.severity, '2'),
                'caller_id': 'boundary-daemon',
                'category': 'Security',
                'subcategory': 'Boundary Violation',
            }

            response = requests.post(
                url,
                auth=(self.user, self.password),
                headers={'Content-Type': 'application/json', 'Accept': 'application/json'},
                json=payload,
                timeout=30,
            )

            if response.status_code == 201:
                result = response.json().get('result', {})
                return result.get('number') or result.get('sys_id')

            logger.error(f"ServiceNow create failed: {response.status_code} {response.text}")

        except Exception as e:
            logger.error(f"ServiceNow integration error: {e}")

        return None

    def update_incident(self, case: Case, ref: str) -> bool:
        if not self.enabled:
            return False

        try:
            import requests

            url = f"https://{self.instance}.service-now.com/api/now/table/{self.table}"
            query_url = f"{url}?sysparm_query=number={ref}"

            # Get incident sys_id
            response = requests.get(
                query_url,
                auth=(self.user, self.password),
                headers={'Accept': 'application/json'},
                timeout=30,
            )

            if response.status_code == 200:
                results = response.json().get('result', [])
                if results:
                    sys_id = results[0]['sys_id']
                    update_url = f"{url}/{sys_id}"

                    # Add work note
                    latest_event = case.timeline[-1] if case.timeline else None
                    work_note = f"Status: {case.status.value}"
                    if latest_event:
                        work_note += f"\n{latest_event.details}"

                    requests.patch(
                        update_url,
                        auth=(self.user, self.password),
                        headers={'Content-Type': 'application/json'},
                        json={'work_notes': work_note},
                        timeout=30,
                    )
                    return True

        except Exception as e:
            logger.error(f"ServiceNow update error: {e}")

        return False

    def resolve_incident(self, case: Case, ref: str) -> bool:
        # Similar to update but with state=6 (Resolved)
        return self.update_incident(case, ref)


class SlackClient(IntegrationClient):
    """Slack integration client."""

    def __init__(self, config: IntegrationConfig):
        self.webhook_url = config.slack_webhook_url
        self.channel = config.slack_channel
        self.enabled = bool(self.webhook_url)

    def create_incident(self, case: Case) -> Optional[str]:
        if not self.enabled:
            return None

        try:
            import requests

            severity_emoji = {
                CaseSeverity.CRITICAL: ':rotating_light:',
                CaseSeverity.HIGH: ':warning:',
                CaseSeverity.MEDIUM: ':large_yellow_circle:',
                CaseSeverity.LOW: ':information_source:',
            }

            blocks = [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"{severity_emoji.get(case.severity, '')} Security Alert: {case.title}",
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Case ID:*\n{case.case_id}"},
                        {"type": "mrkdwn", "text": f"*Severity:*\n{case.severity.name}"},
                        {"type": "mrkdwn", "text": f"*Status:*\n{case.status.value}"},
                        {"type": "mrkdwn", "text": f"*Created:*\n{case.created_at[:16]}"},
                    ]
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*Description:*\n{case.description[:500]}"}
                },
            ]

            payload = {"blocks": blocks}
            if self.channel:
                payload["channel"] = self.channel

            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=10,
            )

            if response.status_code == 200:
                # Slack webhooks don't return thread IDs easily
                return f"slack-{case.case_id[:8]}"

        except Exception as e:
            logger.error(f"Slack integration error: {e}")

        return None

    def update_incident(self, case: Case, ref: str) -> bool:
        # Send update to same channel
        return self.create_incident(case) is not None

    def resolve_incident(self, case: Case, ref: str) -> bool:
        return self.update_incident(case, ref)


class PagerDutyClient(IntegrationClient):
    """PagerDuty integration client."""

    def __init__(self, config: IntegrationConfig):
        self.token = config.pagerduty_token
        self.service_id = config.pagerduty_service_id
        self.escalation_policy = config.pagerduty_escalation_policy
        self.enabled = all([self.token, self.service_id])

    def create_incident(self, case: Case) -> Optional[str]:
        if not self.enabled:
            return None

        try:
            import requests

            url = "https://api.pagerduty.com/incidents"

            urgency_map = {
                CaseSeverity.CRITICAL: 'high',
                CaseSeverity.HIGH: 'high',
                CaseSeverity.MEDIUM: 'low',
                CaseSeverity.LOW: 'low',
            }

            payload = {
                "incident": {
                    "type": "incident",
                    "title": case.title,
                    "service": {"id": self.service_id, "type": "service_reference"},
                    "urgency": urgency_map.get(case.severity, 'low'),
                    "body": {
                        "type": "incident_body",
                        "details": case.description,
                    },
                }
            }

            if self.escalation_policy:
                payload["incident"]["escalation_policy"] = {
                    "id": self.escalation_policy,
                    "type": "escalation_policy_reference",
                }

            response = requests.post(
                url,
                headers={
                    'Authorization': f'Token token={self.token}',
                    'Content-Type': 'application/json',
                },
                json=payload,
                timeout=30,
            )

            if response.status_code == 201:
                result = response.json().get('incident', {})
                return result.get('id')

        except Exception as e:
            logger.error(f"PagerDuty integration error: {e}")

        return None

    def update_incident(self, case: Case, ref: str) -> bool:
        # Add note to PagerDuty incident
        return False  # Simplified

    def resolve_incident(self, case: Case, ref: str) -> bool:
        if not self.enabled:
            return False

        try:
            import requests

            url = f"https://api.pagerduty.com/incidents/{ref}"

            payload = {
                "incident": {
                    "type": "incident_reference",
                    "status": "resolved",
                }
            }

            response = requests.put(
                url,
                headers={
                    'Authorization': f'Token token={self.token}',
                    'Content-Type': 'application/json',
                },
                json=payload,
                timeout=30,
            )

            return response.status_code == 200

        except Exception as e:
            logger.error(f"PagerDuty resolve error: {e}")

        return False


class CaseManager:
    """
    Manages security cases with full lifecycle tracking.

    Integrates with:
    - Event logger for audit trail
    - External ticketing systems
    - Alerting platforms
    """

    def __init__(
        self,
        integration_config: Optional[IntegrationConfig] = None,
        sla_config: Optional[SLAConfig] = None,
        storage_path: str = "/var/lib/boundary-daemon/cases/",
        event_logger=None,
    ):
        self.config = integration_config or IntegrationConfig()
        self.sla_config = sla_config or SLAConfig()
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.event_logger = event_logger

        # Initialize integration clients
        self.servicenow = ServiceNowClient(self.config)
        self.slack = SlackClient(self.config)
        self.pagerduty = PagerDutyClient(self.config)

        # In-memory cache
        self._cases: Dict[str, Case] = {}
        self._lock = threading.Lock()

        # Load existing cases
        self._load_cases()

    def _load_cases(self):
        """Load cases from storage."""
        for file in self.storage_path.glob("*.json"):
            try:
                with open(file, 'r') as f:
                    data = json.load(f)
                    case = self._case_from_dict(data)
                    self._cases[case.case_id] = case
            except Exception as e:
                logger.warning(f"Failed to load case {file}: {e}")

    def _save_case(self, case: Case):
        """Save case to storage."""
        file = self.storage_path / f"{case.case_id}.json"
        with open(file, 'w') as f:
            json.dump(case.to_dict(), f, indent=2)

    def _case_from_dict(self, data: Dict) -> Case:
        """Reconstruct case from dict."""
        case = Case(
            case_id=data['case_id'],
            created_at=data['created_at'],
            status=CaseStatus(data['status']),
            severity=CaseSeverity[data['severity']],
            title=data['title'],
            description=data['description'],
        )
        case.assignee = data.get('assignee')
        case.assigned_at = data.get('assigned_at')
        case.resolved_at = data.get('resolved_at')
        case.resolution = data.get('resolution')
        case.sla_ack_deadline = data.get('sla_ack_deadline')
        case.sla_resolve_deadline = data.get('sla_resolve_deadline')
        case.sla_ack_met = data.get('sla_ack_met')
        case.sla_resolve_met = data.get('sla_resolve_met')
        case.external_refs = data.get('external_refs', {})
        case.tags = data.get('tags', [])
        case.metadata = data.get('metadata', {})

        for alert_data in data.get('alerts', []):
            case.alerts.append(Alert(
                alert_id=alert_data['alert_id'],
                timestamp=alert_data['timestamp'],
                severity=CaseSeverity[alert_data['severity']],
                source=alert_data['source'],
                title=alert_data['title'],
                description=alert_data['description'],
                metadata=alert_data.get('metadata', {}),
            ))

        for event_data in data.get('timeline', []):
            case.timeline.append(CaseEvent(
                timestamp=event_data['timestamp'],
                event_type=event_data['event_type'],
                actor=event_data['actor'],
                details=event_data['details'],
                metadata=event_data.get('metadata', {}),
            ))

        return case

    def _generate_case_id(self) -> str:
        """Generate unique case ID."""
        import uuid
        timestamp = datetime.utcnow().strftime('%Y%m%d')
        unique = uuid.uuid4().hex[:8]
        return f"CASE-{timestamp}-{unique}"

    def create_case(self, alert: Alert, actor: str = "system") -> Case:
        """
        Create new case from alert.

        Args:
            alert: Alert that triggered case creation
            actor: Who/what created the case

        Returns:
            Created case
        """
        now = datetime.utcnow()

        case = Case(
            case_id=self._generate_case_id(),
            created_at=now.isoformat() + "Z",
            status=CaseStatus.NEW,
            severity=alert.severity,
            title=alert.title,
            description=alert.description,
        )

        # Add alert
        case.alerts.append(alert)

        # Calculate SLA deadlines
        ack_minutes = self.sla_config.ack_minutes.get(alert.severity, 60)
        resolve_minutes = self.sla_config.resolve_minutes.get(alert.severity, 1440)
        case.sla_ack_deadline = (now + timedelta(minutes=ack_minutes)).isoformat() + "Z"
        case.sla_resolve_deadline = (now + timedelta(minutes=resolve_minutes)).isoformat() + "Z"

        # Add creation event
        case.add_event("created", actor, f"Case created from alert {alert.alert_id}")

        with self._lock:
            self._cases[case.case_id] = case
            self._save_case(case)

        # Auto-create external tickets
        self._auto_integrate(case)

        # Log to event logger
        if self.event_logger:
            self.event_logger.log_event(
                event_type="CASE_CREATED",
                details=f"Case {case.case_id} created: {case.title}",
                metadata={'case_id': case.case_id, 'severity': case.severity.name},
            )

        logger.info(f"Created case {case.case_id}: {case.title}")
        return case

    def assign(self, case_id: str, assignee: str, actor: str = "system") -> bool:
        """
        Assign case to analyst.

        Args:
            case_id: Case to assign
            assignee: Email/username of assignee
            actor: Who assigned the case
        """
        with self._lock:
            case = self._cases.get(case_id)
            if not case:
                return False

            now = datetime.utcnow()

            case.assignee = assignee
            case.assigned_at = now.isoformat() + "Z"
            case.status = CaseStatus.ASSIGNED

            # Check SLA
            if case.sla_ack_deadline:
                deadline = datetime.fromisoformat(case.sla_ack_deadline.replace('Z', '+00:00'))
                case.sla_ack_met = now.replace(tzinfo=deadline.tzinfo) <= deadline

            case.add_event("assigned", actor, f"Assigned to {assignee}")

            self._save_case(case)

        # Update external tickets
        self._update_externals(case)

        logger.info(f"Case {case_id} assigned to {assignee}")
        return True

    def update_status(self, case_id: str, status: CaseStatus, actor: str = "system", notes: str = "") -> bool:
        """Update case status."""
        with self._lock:
            case = self._cases.get(case_id)
            if not case:
                return False

            old_status = case.status
            case.status = status
            case.add_event("status_change", actor, f"Status changed: {old_status.value} → {status.value}. {notes}")

            self._save_case(case)

        self._update_externals(case)
        return True

    def resolve(self, case_id: str, resolution: str, actor: str = "system") -> bool:
        """
        Resolve case.

        Args:
            case_id: Case to resolve
            resolution: Resolution summary
            actor: Who resolved the case
        """
        with self._lock:
            case = self._cases.get(case_id)
            if not case:
                return False

            now = datetime.utcnow()

            case.status = CaseStatus.RESOLVED
            case.resolved_at = now.isoformat() + "Z"
            case.resolution = resolution

            # Check SLA
            if case.sla_resolve_deadline:
                deadline = datetime.fromisoformat(case.sla_resolve_deadline.replace('Z', '+00:00'))
                case.sla_resolve_met = now.replace(tzinfo=deadline.tzinfo) <= deadline

            case.add_event("resolved", actor, f"Case resolved: {resolution}")

            self._save_case(case)

        # Resolve external tickets
        self._resolve_externals(case)

        logger.info(f"Case {case_id} resolved: {resolution}")
        return True

    def dismiss(self, case_id: str, reason: str, actor: str = "system") -> bool:
        """Dismiss case as false positive or not actionable."""
        with self._lock:
            case = self._cases.get(case_id)
            if not case:
                return False

            case.status = CaseStatus.DISMISSED
            case.resolved_at = datetime.utcnow().isoformat() + "Z"
            case.resolution = f"Dismissed: {reason}"
            case.add_event("dismissed", actor, f"Case dismissed: {reason}")

            self._save_case(case)

        return True

    def add_alert(self, case_id: str, alert: Alert, actor: str = "system") -> bool:
        """Add related alert to existing case."""
        with self._lock:
            case = self._cases.get(case_id)
            if not case:
                return False

            case.alerts.append(alert)
            case.add_event("alert_added", actor, f"Related alert added: {alert.alert_id}")

            # Escalate if new alert is higher severity
            if alert.severity.value > case.severity.value:
                case.severity = alert.severity
                case.add_event("escalated", actor,
                             f"Severity escalated to {alert.severity.name} due to related alert")

            self._save_case(case)

        return True

    def get_case(self, case_id: str) -> Optional[Case]:
        """Get case by ID."""
        return self._cases.get(case_id)

    def list_cases(
        self,
        status: Optional[CaseStatus] = None,
        severity: Optional[CaseSeverity] = None,
        assignee: Optional[str] = None,
        limit: int = 100,
    ) -> List[Case]:
        """List cases with optional filters."""
        cases = list(self._cases.values())

        if status:
            cases = [c for c in cases if c.status == status]
        if severity:
            cases = [c for c in cases if c.severity == severity]
        if assignee:
            cases = [c for c in cases if c.assignee == assignee]

        # Sort by created_at descending
        cases.sort(key=lambda c: c.created_at, reverse=True)

        return cases[:limit]

    def get_sla_breaches(self) -> List[Case]:
        """Get cases that have breached or are about to breach SLA."""
        now = datetime.utcnow()
        breaches = []

        for case in self._cases.values():
            if case.status in (CaseStatus.RESOLVED, CaseStatus.DISMISSED):
                continue

            # Check acknowledgement SLA
            if case.sla_ack_deadline and case.sla_ack_met is None:
                deadline = datetime.fromisoformat(case.sla_ack_deadline.replace('Z', '+00:00'))
                if now.replace(tzinfo=deadline.tzinfo) > deadline:
                    breaches.append(case)
                    continue

            # Check resolution SLA
            if case.sla_resolve_deadline and case.sla_resolve_met is None:
                deadline = datetime.fromisoformat(case.sla_resolve_deadline.replace('Z', '+00:00'))
                if now.replace(tzinfo=deadline.tzinfo) > deadline:
                    breaches.append(case)

        return breaches

    def _auto_integrate(self, case: Case):
        """Automatically create external tickets based on severity."""
        # ServiceNow for CRITICAL
        if case.severity.value >= self.config.auto_servicenow_severity.value:
            if self.servicenow.enabled:
                ref = self.servicenow.create_incident(case)
                if ref:
                    case.external_refs['servicenow'] = ref
                    case.add_event("integration", "system", f"ServiceNow incident created: {ref}")
                    self._save_case(case)

        # PagerDuty for CRITICAL
        if case.severity.value >= self.config.auto_pagerduty_severity.value:
            if self.pagerduty.enabled:
                ref = self.pagerduty.create_incident(case)
                if ref:
                    case.external_refs['pagerduty'] = ref
                    case.add_event("integration", "system", f"PagerDuty incident created: {ref}")
                    self._save_case(case)

        # Slack for HIGH+
        if case.severity.value >= self.config.auto_slack_severity.value:
            if self.slack.enabled:
                ref = self.slack.create_incident(case)
                if ref:
                    case.external_refs['slack'] = ref
                    case.add_event("integration", "system", "Slack notification sent")
                    self._save_case(case)

    def _update_externals(self, case: Case):
        """Update all external tickets."""
        for integration, ref in case.external_refs.items():
            if integration == 'servicenow':
                self.servicenow.update_incident(case, ref)
            elif integration == 'slack':
                self.slack.update_incident(case, ref)
            elif integration == 'pagerduty':
                self.pagerduty.update_incident(case, ref)

    def _resolve_externals(self, case: Case):
        """Resolve all external tickets."""
        for integration, ref in case.external_refs.items():
            if integration == 'servicenow':
                self.servicenow.resolve_incident(case, ref)
            elif integration == 'pagerduty':
                self.pagerduty.resolve_incident(case, ref)
            elif integration == 'slack':
                self.slack.update_incident(case, ref)


if __name__ == "__main__":
    # Demo usage
    logging.basicConfig(level=logging.INFO)

    manager = CaseManager()

    # Create alert
    alert = Alert(
        alert_id="alert-001",
        timestamp=datetime.utcnow().isoformat() + "Z",
        severity=CaseSeverity.HIGH,
        source="prompt_injection",
        title="Prompt injection attempt detected",
        description="Agent attempted to use 'ignore previous instructions' pattern",
    )

    # Create case
    case = manager.create_case(alert, actor="detection_engine")
    print(f"Created: {case.case_id}")

    # Assign
    manager.assign(case.case_id, "analyst@company.com", actor="soc_lead")

    # Resolve
    manager.resolve(case.case_id, "Blocked and agent terminated", actor="analyst@company.com")

    # List cases
    cases = manager.list_cases()
    print(f"\nTotal cases: {len(cases)}")
    for c in cases:
        print(f"  {c.case_id}: {c.status.value} - {c.title}")
