Boundary Daemon Specification
Purpose
The Boundary Daemon acts as the sovereign trust enforcer in the human-centric AI ecosystem. It defines and defends the "trusted space" where interactions occur, ensuring no sensitive data leaks outward, no unauthorized actions execute, and no learning/recall happens without explicit consent.
It addresses user fears head-on: "I'm not feeding the beast." All processing stays local by default. Sensitive information (like SSNs, addresses, financial details) never leaves the user's device without deliberate, confirmed permission. The daemon fails closed—blocking rather than risking exposure.
Design Principles

Local-First Privacy — All detection, redaction, and enforcement run on-device. No data sends to clouds unless the user creates a Learning Contract allowing it.
Fail-Closed Security — Ambiguous or unapproved situations default to block/deny.
Human Supremacy — Users override any daemon decision; no autonomous escalation without consent.
Transparency — Users see plain-language explanations for every block, alert, or redaction.
Composable — Stacks with Memory Vault (refuses unsafe writes), Learning Contracts (enforces scopes), and external modules.
Proactive Protection — Monitors for external exposures (e.g., fraud listings, data leaks) with user-defined rules.

Trust Boundary Modes
The daemon operates in escalating modes, set manually or via contracts:

Isolated → No external network access; all LLMs local-only.
Standard → Local processing + safe outbound (e.g., anonymized queries); PII auto-redacted.
Trusted → Allows controlled escalation (e.g., cloud LLM with redacted input); requires confirmation.
Open → Minimal restrictions (user-explicit only, for advanced cases).

Downgrading modes suspends dependent operations (e.g., strategic learning).
Core Features
1. PII Detection & Redaction Pipeline

Built on Microsoft Presidio (open-source, local) as the primary engine.
Supports 180+ entities: SSN, credit cards, addresses, phone, email, driver's license, passport, bank accounts, etc.
Pluggable enhancers: spaCy NER, regex, context-aware scoring, custom recognizers.
Actions:
Detect — Scan all inputs/outputs/memory candidates.
Redact/Mask — Replace with [REDACTED], tokens (e.g., <SSN_1>), or hashes.
Block — Halt operation if high-risk PII detected and not allowed.
Alert — Notify user in plain language: "Detected possible SSN—blocked to protect you."

Configurable thresholds per entity (e.g., higher confidence for SSN).

2. Data Flow Enforcement Points
Mandatory checks at key hooks:

Inbound (User → System) → Scan prompts/interactions; redact/block risky PII before processing.
Internal (LLM Processing) → Ensure no unredacted PII enters local models or memory.
Outbound (Escalation/Export) → Strict redaction before any cloud send; require user confirmation + Learning Contract.
Memory Operations → Validate against contracts; reject writes with forbidden PII.
Recall/Output → Re-scan and redact before presenting to user.

3. Proactive Exposure Monitoring
Optional module (activated via plain-language contract):

User defines "protected assets" (e.g., SSN, home address, VIN, phone, email).
Periodic safe scans:
Dark Web/breach checks (via local integration with HaveIBeenPwned offline DB or anonymized API).
Web alerts (Google Alerts-style for asset + "for sale"/"exposed").
Fraud listing detection (e.g., unauthorized property/car ads).

Alerts only—no auto-actions beyond notification.
Plain-language setup: "Monitor my SSN for dark web exposure?"

4. Integration Points

Learning Contracts → Enforces scope (e.g., blocks generalization if PII involved).
Memory Vault → Refuses storage of unredacted high-classification data.
Synth Mind / Agent-OS → Intercepts tool calls; blocks risky external actions.
IntentLog → Logs all boundary decisions as auditable prose entries.

Human UX Requirements

All decisions explained in plain language (e.g., "I blocked this because it looks like a credit card number—want to override?").
Dashboard shows current mode, active monitors, recent blocks/alerts.
One-click overrides with confirmation ceremony for high-risk actions.
No dark patterns — defaults to maximum privacy.

Threat Model & Mitigations

ThreatMitigationAccidental PII leakage to cloud LLMMandatory local redaction + confirmation before sendSSN/address exposure on webProactive monitoring + instant alertsPrompt injection bypassing safeguardsInput validation + output filteringOverly aggressive blockingUser overrides + tunable thresholdsData persistence in memoryContract-bound classification + tombstoning
Implementation Notes

Core: Python service (Ubuntu-native).
Primary library: Presidio (analyzer + anonymizer).
Extendable: Add custom recognizers for domain-specific PII.
Lightweight: Runs in background; minimal resource use.
Open-source: Part of the ecosystem repos.

This spec makes the Boundary Daemon a true privacy guardian—proactive yet non-intrusive, empowering users to feel fully safe and in control. No data ever "feeds the beast" without explicit, informed consent.
