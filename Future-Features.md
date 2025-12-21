Boundary Daemon - New Features Sheet: Log Watchdog Agent
Version: 1.0
Status: Proposed
Last Updated: 2025-12-21
Maintained By: Boundary Daemon Development Team
Overview
This feature introduces a Log Watchdog Agent—an optional, LLM-powered observer that tails application logs in real-time, detects anomalies/errors, summarizes issues in plain English, and offers proactive lookup for fixes. It enhances the Daemon's proactive security by catching runtime issues early, without interfering with core logic.
Integrated as an optional module, it aligns with principles like "Fail-Closed" (ignores trivial warnings) and "Human Supremacy" (user confirmation for lookups/actions). It stacks with existing components: uses Event Logger for audits, Policy Engine for mode restrictions (e.g., no web lookups in AIRGAP), and Biometric Ceremony for sensitive overrides.
Purpose

Detect & Summarize Issues: Turn raw logs (e.g., exceptions, warnings) into actionable insights, reducing debugging time.
Proactive Assistance: Optionally search for fixes, educating users and preventing escalation.
Security Enhancement: Spot patterns like resource leaks or auth failures that could indicate attacks/exploits.
Non-Intrusive: Sandboxed from production; no auto-fixes to avoid loops or risks.

Architecture Overview

Primary Program Layer
Core Daemon logic emits structured JSON logs or stderr (e.g., via Python's logging module).
Example: {"level":"error","timestamp":"2025-12-21T10:00:00Z","module":"network","message":"ConnectionRefusedError: [Errno 111] Connection refused"}.

Observer / Watchdog Agent (Local LLM)
Tails logs (e.g., via tail -f, file watcher, or websocket).
Scans for patterns: errors, exceptions, warnings (e.g., "leak", "bind failed", "permission denied").
Uses local LLM (e.g., Llama 3 via Ollama) to summarize: "Network module failed to connect—likely due to firewall or unavailable service."
Severity classifier: Ignores low-impact (e.g., debug logs); flags medium/high for user prompt.
Prompts user: "Issue detected. Want me to lookup fixes online?" (Requires Learning Contract for web access).

Lookup Agent (LLM + Web Integration)
If approved, spawns a secondary LLM instance.
Crafts search query from summary (e.g., "Python ConnectionRefusedError Errno 111 fixes").
Parses results (top StackOverflow, GitHub Issues, docs) for causes/fixes.
Returns: "Common fix: Check port availability with netstat -tuln. Or retry with exponential backoff."


Implementation Path

Core Tools: Python asyncio for async log tailing; logging hooks for structured output; psutil for resource anomalies (e.g., high CPU indicating leaks).
LLM Integration: Local-first (Ollama/Llama); optional cloud escalation under Trusted mode + Contract.
Dependencies: ollama (local inference); aiofiles (async file reading); optional sentry_sdk for enhanced tracing.

Sample Code (daemon/watchdog/log_watchdog.py)
Pythonimport asyncio
import json
from ollama import Client  # Local LLM client
from daemon.policy_engine import PolicyEngine  # For mode checks

class LogWatchdog:
    def __init__(self, log_path: str, policy_engine: PolicyEngine):
        self.log_path = log_path
        self.policy = policy_engine
        self.llm = Client(host='http://localhost:11434')  # Local Ollama
        self.severity_threshold = 'medium'  # Configurable

    async def monitor_logs(self):
        """Tail logs and analyze anomalies"""
        process = await asyncio.create_subprocess_exec(
            "tail", "-f", self.log_path,
            stdout=asyncio.subprocess.PIPE
        )
        while True:
            line = await process.stdout.readline()
            if not line:
                break
            msg = line.decode().strip()
            try:
                log_entry = json.loads(msg)  # Assume structured JSON
                if log_entry.get('level', '').lower() in ['error', 'warning']:
                    await self.analyze_entry(log_entry)
            except json.JSONDecodeError:
                # Fallback for unstructured logs
                if any(keyword in msg.lower() for keyword in ['error', 'exception', 'warning']):
                    await self.analyze_entry({'message': msg})

    async def analyze_entry(self, entry: dict):
        """LLM-summarize and classify"""
        prompt = f"Summarize this log error in plain English, classify severity (low/medium/high), and suggest if lookup needed:\n{json.dumps(entry)}"
        response = self.llm.generate(model='llama3', prompt=prompt)
        summary = response['response']
        severity = self.extract_severity(summary)  # Parse from output
        
        if severity >= self.severity_threshold:
            # Log to Event Logger
            self.policy.daemon.event_logger.log_event('WATCHDOG_ALERT', summary)
            # User prompt (e.g., via CLI or notification)
            if await self.user_confirm("Issue: {summary}. Lookup fixes?"):
                await self.perform_lookup(summary)

    async def perform_lookup(self, summary: str):
        """Web-integrated lookup (if mode allows)"""
        if not self.policy.check_web_access():  # Tie to Boundary Mode
            return "Web lookup denied in current mode."
        
        query = f"{summary} common fixes site:stackoverflow.com OR site:github.com/issues"
        # Use web_search tool (from available tools)
        search_results = await web_search(query)  # Pseudo-call; integrate actual tool
        lookup_prompt = f"From these results, extract top fixes:\n{search_results}"
        fixes = self.llm.generate(model='llama3', prompt=lookup_prompt)['response']
        print(f"Recommended fixes: {fixes}")

    def extract_severity(self, summary: str) -> str:
        # Simple parser; enhance with regex/LLM
        return 'high' if 'critical' in summary else 'medium'  # etc.

    async def user_confirm(self, prompt: str) -> bool:
        # Integrate with CeremonyManager for secure confirmation
        return await self.policy.daemon.ceremony_manager.perform_ceremony(prompt)
Enhancements

Severity Classifier: LLM-fine-tuned on log datasets; ignore trivia.
Auto-Lookup Mode: Toggle via Contract; searches SO, GitHub, internal wikis.
Notifications: Integrate PagerDuty/Slack for summaries; tie to Tripwire for security alerts.
Resource Anomalies: Use psutil to flag CPU/memory spikes as "leaks."
Auditability: All watchdog actions logged immutably; no dynamic fixes to prevent loops.

Benefits & Tie-Ins

Game-Theoretic Win: Rewards proactive monitoring; deters neglect by making fixes easy/visible.
Privacy/Security: Local LLM default; web lookups require Contract + Mode check.
Scalability: Runs async; low overhead.

This feature elevates the Daemon from gatekeeper to intelligent sentinel. Prioritize after core enforcement (Plan 1). 🚀922msExpertIntegrate with OpenTelemetryBoundary Daemon - New Features Sheet: OpenTelemetry Integration
Version: 1.1
Status: Proposed
Last Updated: 2025-12-21
Maintained By: Boundary Daemon Development Team
Overview
This feature adds native OpenTelemetry (OTel) integration to the Boundary Daemon, enabling structured, standardized observability across traces, metrics, and logs. It elevates the existing Log Watchdog Agent and overall system monitoring from ad-hoc log tailing to a professional-grade, vendor-neutral telemetry pipeline.
OpenTelemetry provides:

Distributed tracing (context propagation across components)
Structured logs with trace correlation
Metrics (e.g., mode transitions, ceremony counts, violation rates)
Seamless export to backends (Jaeger, Prometheus, Loki, Honeycomb, etc.)

This integration preserves all core principles: local-first by default, optional export under strict control, human supremacy, and fail-closed behavior.
Purpose

End-to-End Visibility: Correlate events across daemon subsystems (Policy Engine → Tripwire → Event Logger → Watchdog).
Enhanced Watchdog Intelligence: Feed structured traces/logs directly into the Watchdog Agent—no fragile tailing.
Security Auditing: Export immutable, tamper-evident telemetry for compliance or forensics.
Performance Insights: Measure ceremony latency, mode transition times, scan durations.
Future-Proofing: Standard format enables integration with enterprise observability stacks.

Architecture Integration
The OTel SDK becomes the central instrumentation layer:
textPrimary Program (Daemon Core)
        │
        ▼
OpenTelemetry SDK (TracerProvider, MeterProvider, LoggerProvider)
        │
        ├─► Traces → Span events (e.g., "mode_transition", "ceremony_start")
        ├─► Metrics → Counters/Gauges (e.g., violations_total, current_mode)
        └─► Logs → Structured records (replaces raw file appends optionally)
        │
        ▼
OTLP Exporter (configurable)
  ├─► Console (default, local-only)
  ├─► File (local JSON/Proto)
  └─► Remote Endpoint (only if allowed by mode + contract)
Key Integration Points

Event Logger
Augment or replace hash-chain file with OTel Logs (structured + correlated to traces).
Maintain backward compatibility: continue writing hash-chained file for immutability proof.

Log Watchdog Agent
Subscribe directly to OTel Log Pipeline (no tail -f needed).
Receive structured records with trace/span IDs for richer context.
Example: Correlate a "network_violation" log with the exact mode_transition span that triggered it.

Policy Engine & Tripwire
Instrument decisions as spans: policy.check_recall, tripwire.detect_usb.
Add attributes: mode=current, memory_class=3, violation_type=network_in_airgap.

Ceremony Manager
Span: ceremony.perform with duration metric and biometric result attribute.

Code Vulnerability Advisor
Span per scan: security.scan_repository with attributes like repo_path, advisory_count.


Implementation Plan
Plan 8: OpenTelemetry Integration (Priority: HIGH – Observability)
Duration: 4-6 weeks
Dependencies: opentelemetry-api, opentelemetry-sdk, opentelemetry-exporter-otlp-proto-grpc, opentelemetry-instrumentation-logging
Phase 1: Core Instrumentation (2-3 weeks)
Python# daemon/telemetry/otel_setup.py

from opentelemetry import trace, metrics, logs
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.logs import LoggerProvider, LoggingHandler
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.grpc.logs_exporter import OTLPLogExporter
import logging

def init_telemetry(daemon):
    resource = Resource(attributes={
        "service.name": "boundary-daemon",
        "service.instance.id": daemon.instance_id,
        "host.name": daemon.hostname
    })

    # Traces
    trace.set_tracer_provider(TracerProvider(resource=resource))
    tracer = trace.get_tracer(__name__)

    # Metrics
    metrics.set_meter_provider(MeterProvider(resource=resource))
    meter = metrics.get_meter(__name__)
    violations_counter = meter.create_counter(
        "boundary.violations", description="Number of security violations"
    )
    mode_duration = meter.create_histogram(
        "boundary.mode.duration", unit="s", description="Time spent in each mode"
    )

    # Logs
    logs.set_logger_provider(LoggerProvider(resource=resource))
    logger = logs.get_logger(__name__)

    # Console exporter (always on)
    from opentelemetry.sdk.trace.export import ConsoleSpanExporter
    trace.get_tracer_provider().add_span_processor(
        BatchSpanProcessor(ConsoleSpanExporter())
    )

    # Conditional remote export
    if daemon.policy.check_telemetry_export():  # Requires TRUSTED+ mode + Contract
        trace.get_tracer_provider().add_span_processor(
            BatchSpanProcessor(OTLPSpanExporter(endpoint="otel-collector:4317"))
        )
        metrics.get_meter_provider().add_metric_processor(
            PeriodicExportingMetricReader(OTLPMetricExporter(endpoint="otel-collector:4317"))
        )
        logs.get_logger_provider().add_log_record_processor(
            BatchLogRecordProcessor(OTLPLogExporter(endpoint="otel-collector:4317"))
        )

    # Integrate with Python logging
    handler = LoggingHandler(level=logging.INFO, logger_provider=logs.get_logger_provider())
    logging.getLogger().addHandler(handler)

    return tracer, meter, logger
Phase 2: Subsystem Instrumentation (1-2 weeks)

Wrap key methods with @tracer.start_as_current_span("name")
Emit metrics on violations, mode changes, ceremony outcomes.
Replace raw print/file logs with logging.getLogger() → OTel structured logs.

Phase 3: Watchdog Enhancement (1 week)
Python# Watchdog now consumes OTel logs directly
class LogWatchdog:
    def __init__(..., log_processor):
        self.log_processor = log_processor  # Subscribe to OTel log pipeline

    def on_log_record(self, log_record):
        if log_record.attributes.get('level') in ['ERROR', 'WARNING']:
            self.analyze_record(log_record)
Configuration
Add to /etc/boundary-daemon/boundary.conf:
ini[telemetry]
enabled = true
export_remote = false  # Requires explicit Learning Contract
otel_endpoint = "http://localhost:4318"  # OTLP/gRPC
console_export = true
log_correlation = true
Benefits

Richer Debugging: Trace an override ceremony back to the exact recall attempt.
Security Analytics: Query violation patterns over time.
Interoperability: Export to any OTel-compatible backend.
Watchdog Supercharged: No parsing fragility; full context from traces.

Security & Privacy Controls

Export disabled by default (AIRGAP/COLDROOM block it entirely).
Requires explicit Learning Contract: “Allow telemetry export to monitoring endpoint.”
All exported data redacted of sensitive attributes (e.g., memory contents) via OTel processor.

This integration transforms the Daemon into a fully observable, enterprise-ready security foundation—while keeping privacy and control paramount.
Ready to slot this in after kernel enforcement and biometric rollout. 🚀



🔍 Strategic Summary
Feature	Role	Priority	Dependencies	Key Benefit
Log Watchdog Agent (v1.0)	Intelligent anomaly summarizer + lookup assistant	MEDIUM	asyncio, ollama, Policy Engine, Event Logger	Converts runtime noise into actionable intelligence
OpenTelemetry Integration (v1.1)	Unified observability backbone (traces / metrics / logs)	HIGH	opentelemetry-api, opentelemetry-sdk, Event Logger, Watchdog	Enterprise-grade telemetry with zero-trust export control
🧠 Design Validation
✅ Log Watchdog Agent

Strengths

Local-first LLM (no silent network calls).

Aligns with Fail-Closed — ignores trivial logs.

Integrates with Policy Engine for mode-based web lookup control.

Auditable via Event Logger → OTel log pipeline.

Enhancements

Back-pressure control: throttle LLM calls with token bucket to avoid overload during bursty errors.

Error taxonomy: maintain small YAML rulebase mapping common exceptions → severity (faster than full LLM pass).

Learning Contract UI: expose toggle in admin CLI to grant temporary web lookup rights.

Telemetry link: emit span watchdog.analysis with attributes severity, module, lookup_performed.

✅ OpenTelemetry Integration

Strengths

Unifies trace + metric + log context for post-incident forensics.

Local JSON/console export maintains air-gap compliance.

Bridges Event Logger → Watchdog with structured data instead of fragile tailing.

Provides groundwork for SLA analytics (ceremony latency, policy decision timing).

Enhancements

Add SpanProcessor chain for redaction of sensitive fields (payload, biometric_hash).

Introduce custom resource attributes:

"boundary.mode": daemon.current_mode,
"boundary.contract.id": daemon.contract_id,
"boundary.user.confirmed": True


Extend Meter metrics:

boundary.watchdog.alerts_total

boundary.lookup.requests_total

boundary.ceremony.latency_histogram

Testing: use OTel In-Memory Exporter in CI to assert trace/metric emission counts.

⚙️ Integration Sequence (Recommended)

Phase A: Finish Plan 6 (Biometrics + TPM).

Phase B: Implement OpenTelemetry Core (Plan 8 Phase 1 + 2).

Phase C: Refactor Watchdog Agent to subscribe to OTel Logs Processor.

Phase D: Add Policy Engine bridging for Learning Contract & export gating.

Phase E: Conduct Security Audit (ensure no cross-mode data leakage).

🔐 Governance & Compliance

AIRGAP / COLDROOM Modes: enforce export_remote = false hard stop.

Learning Contracts: human-signed YAML artifacts enabling temporary capabilities (telemetry export / web lookup).

Event Provenance: each Watchdog suggestion generates immutable event:

{"type":"WATCHDOG_RECOMMEND","severity":"high","summary":"auth token expired","lookup":"performed"}
