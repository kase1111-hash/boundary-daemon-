Boundary Daemon Specification
1. Purpose

The Boundary Daemon (BD) is a hard enforcement layer that defines and maintains trust boundaries for a learning co‑worker system. It determines where cognition is allowed to flow and where it must stop.

If the Memory Vault is the safe, the Boundary Daemon is the armed guard + walls + air‑gap switches.

The daemon is authoritative. Other subsystems must not override it.

2. Core Responsibilities

Environment Sensing – Detect current trust conditions

Mode Enforcement – Enforce boundary modes

Recall Gating – Permit or deny memory recall

Execution Gating – Restrict tools, IO, models

Tripwire Response – Lock down on violation

Audit Signaling – Emit immutable boundary events

3. Boundary Modes (Global State)

Only ONE mode may be active at a time.

Mode	Description	Typical Use
Open	Networked, low trust	Casual use
Restricted	Network allowed, memory limited	Research
Trusted	Offline or verified LAN	Serious work
Air‑Gap	Physically isolated	High‑value IP
Cold Room	No IO except keyboard/display	Crown‑jewel thinking
Lockdown	Emergency freeze	Threat response

Mode transitions are explicit and logged.

4. Environment Sensing

The daemon continuously samples:

4.1 Network State

Active interfaces

Route table changes

DNS queries

VPN tunnels

4.2 Hardware State

USB insertion

New block devices

Camera / mic availability

TPM / Secure Enclave presence

4.3 Software State

External model endpoints enabled

Shell escape attempts

Privilege escalation

Unexpected child processes

4.4 Human Presence Signals (Optional)

Keyboard activity

Screen unlock

Biometric confirmation

5. Policy Engine

Policies map (mode × signal × request) → decision.

5.1 Policy Properties

Deterministic

Fail‑closed

Human‑overridable (with ceremony)

5.2 Example Policy
IF mode >= Air‑Gap
AND network == active
THEN transition → Lockdown
6. Enforcement Hooks

The Boundary Daemon exposes a read‑only API and a command socket.

6.1 Mandatory Callers

Memory Vault (recall)

Agent‑OS (tool use)

synth‑mind (reflection loops)

External model adapters

If a component bypasses BD, this is a fatal architecture violation.

7. Core Schemas
7.1 Boundary State
{
  "mode": "open|restricted|trusted|airgap|coldroom|lockdown",
  "network": "offline|online",
  "hardware_trust": "low|medium|high",
  "external_models": false,
  "last_transition": "timestamp",
  "operator": "human|system"
}
7.2 Boundary Event Log
{
  "event_id": "uuid",
  "timestamp": "ts",
  "event_type": "mode_change|violation|tripwire",
  "details": "string",
  "hash_chain": "prev_hash"
}

Logs are append‑only and tamper‑evident.

8. Recall Gating Rules

The daemon enforces minimum environment requirements:

Memory Class	Minimum Mode
0–1	Open
2	Restricted
3	Trusted
4	Air‑Gap
5	Cold Room

Violation results in automatic denial.

9. Tool & IO Restrictions

Examples:

Air‑Gap:

No network

No USB

No external models

Cold Room:

Display + keyboard only

No filesystem writes

No recall > class 3 unless owner unlock

Restrictions are enforced at OS and application layers.

10. Tripwires

Tripwires trigger immediate Lockdown.

Examples

Network comes online in Air‑Gap

USB inserted in Cold Room

Unauthorized recall attempt

Boundary daemon killed or paused

Lockdown behavior:

Freeze recall

Halt agent execution

Require human intervention

11. Human Override (Ceremony)

Overrides require:

Physical presence

Multi‑step confirmation

Cooldown delay

Immutable log entry

No silent overrides. Ever.

12. Failure Model

If BD crashes → system enters Lockdown

If signals are ambiguous → fail closed

If clocks drift → freeze mode transitions

13. Threat Model
Adversaries

Remote attackers

Local malware

Rogue agents

Accidental owner misuse

Key Risks & Mitigations
Risk	Mitigation
Boundary bypass	Mandatory hooks
Gradual erosion	Immutable logs
Owner impatience	Ceremony + cooldown
Supply‑chain attack	Offline verification
14. Non‑Goals

Performance optimization

User convenience

Stealth operation

Security is allowed to be annoying.

15. Implementation Notes

Runs as privileged system service

Minimal dependencies

No network listeners

Written in memory‑safe language

16. Design Constraint

If the system cannot clearly answer “where am I allowed to think right now?” it is not safe to think at all.

The Boundary Daemon exists to answer that question.
