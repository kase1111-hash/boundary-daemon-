# Boundary Daemon Monitoring Metrics

Comprehensive catalog of all security rules, tests, threats, and monitoring points.

## Summary Statistics

| Category | Count | Performance Impact |
|----------|-------|-------------------|
| **Policy Rules** | 15 | Low - evaluated on request |
| **Security Tests** | 516 test cases | N/A - test time only |
| **Attack Vectors** | 78+ | N/A - detection patterns |
| **Monitoring Points** | 47 | Medium - 1Hz polling |
| **API Commands** | 23 | Low - on-demand |
| **Security Gates** | 38 | Low - evaluated on request |
| **Event Types** | 26 | Low - async logging |
| **Enforcement Modules** | 11 | Low - triggered on change |
| **Integration Modules** | 12 | N/A - external repos |

**Total Active Monitoring Elements: 743+**

---

## Monitoring Intervals (Performance Configuration)

### Core Polling Intervals

| Monitor | Interval | Config Location |
|---------|----------|-----------------|
| State Monitor | 1.0s | `constants.py:STATE_POLL_INTERVAL` |
| Health Check | 60.0s | `constants.py:HEALTH_CHECK_INTERVAL` |
| Heartbeat | 10.0s | `health_monitor.py:heartbeat_interval` |
| Enforcement Loop | 5.0s | `constants.py:ENFORCEMENT_INTERVAL` |
| File Integrity | 60.0s | `constants.py:INTEGRITY_CHECK_INTERVAL` |
| Dead-man Check | 60.0s | `constants.py:DEAD_MAN_CHECK_INTERVAL` |
| Memory Sampling | 5.0s | `memory_monitor.py:sample_interval` |
| Resource Sampling | 10.0s | `resource_monitor.py:sample_interval` |
| Mode Advisor | 60.0s | `mode_advisor.py:evaluation_interval` |
| Log Redundancy | 60.0s | `redundant_event_logger.py:health_check_interval` |

### Cache TTLs (Performance Optimization)

| Cache | TTL | Max Size |
|-------|-----|----------|
| Threat Intel | 3600s (1h) | 10,000 entries |
| LDAP Groups | 300s (5m) | Unlimited |
| LDAP Users | 60s (1m) | Unlimited |
| OIDC JWKS | 3600s (1h) | Single |
| OIDC Tokens | 300s (5m) | Unlimited |
| Identity | 300s (5m) | Unlimited |
| TPM PCRs | 5s | 24 entries |
| Malware Bazaar | 3600s (1h) | 10,000 entries |
| Daemon Status | 1s | Single |

---

## Detailed Component Counts

### 1. Policy Rules (15)

**Core Policy Files:**
- `config/policies.d/00-examples.yaml` - 6 example rules
- `config/policies.d/10-organization-policies.yaml.example` - 5 template rules
- `daemon/policy_engine.py` - 4 evaluation methods

**Named Rules:**
1. Block external models in AIRGAP/COLDROOM
2. Require VPN for confidential memories
3. Allow safe filesystem tools in OPEN/RESTRICTED
4. Block network tools in AIRGAP
5. Limit SECRET access to business hours
6. No USB in COLDROOM
7. Require VPN for all network operations
8. Block unauthorized API access
9. Contractor hours restriction
10. CROWN_JEWEL requires COLDROOM
11. Whitelist approved tools only
12. Rate limit enforcement per mode
13. Authority level validation
14. Reflection depth limits
15. Cross-agent communication rules

### 2. Security Tests (516 cases)

| Test File | Cases | Coverage |
|-----------|-------|----------|
| test_attack_simulations.py | 75 | Attack prevention |
| test_state_monitor.py | 59 | State detection |
| test_privilege_manager.py | 48 | Privilege control |
| test_policy_engine.py | 48 | Policy evaluation |
| test_health_monitor.py | 45 | Health checking |
| test_event_logger.py | 37 | Event logging |
| test_tripwires.py | 36 | Violation detection |
| test_api_auth.py | 34 | Authentication |
| test_log_hardening.py | 27 | Log security |
| test_append_only.py | 27 | Append-only storage |
| test_constants.py | 26 | Configuration |
| test_integrations.py | 16 | Integrations |
| test_security_stack_e2e.py | 11 | End-to-end |
| test_security_integration.py | 27 | Cross-repo security |

### 3. Attack Vectors (78+)

**64 Attack Simulations by Category:**

| Category | Count | Examples |
|----------|-------|----------|
| Cellular Attacks | 5 | 2G downgrade, IMSI catcher, tower switching |
| WiFi Attacks | 9 | Evil twin, deauth, rogue AP, handshake capture |
| DNS Attacks | 8 | Tunneling, rebinding, spoofing, TLD abuse |
| ARP Attacks | 5 | Spoofing, gateway impersonation, MITM |
| Threat Intel | 7 | TOR exit, C2, botnet, beaconing |
| File Integrity | 8 | Modification, SUID, world writable |
| Traffic Anomaly | 8 | Port scan, exfiltration, ICMP tunnel |
| Process Security | 8 | ptrace, LD_PRELOAD, memfd exec |
| Network Bypass | 6 | VPN tunnel, bridge, protocol abuse |

**14 MITRE ATT&CK Tactics:**
TA0001-TA0011, TA0040, TA0042, TA0043

**10 Violation Types:**
1. NETWORK_IN_AIRGAP
2. USB_IN_COLDROOM
3. UNAUTHORIZED_RECALL
4. DAEMON_TAMPERING
5. MODE_INCOMPATIBLE
6. EXTERNAL_MODEL_VIOLATION
7. SUSPICIOUS_PROCESS
8. HARDWARE_TRUST_DEGRADED
9. CLOCK_MANIPULATION
10. NETWORK_TRUST_VIOLATION

### 4. Monitoring Points (47)

**State Monitor (42 methods):**
- Core: `_check_network`, `_check_hardware`, `_check_software`, `_check_human_presence`
- Security: `_check_dns_security`, `_check_arp_security`, `_check_wifi_security`
- Intel: `_check_threat_intel`, `_check_file_integrity`, `_check_traffic_anomaly`
- Process: `_check_process_security`, `_check_specialty_networks`
- Devices: `_detect_lora_devices`, `_detect_thread_devices`, `_detect_cellular_security_threats`

**Tripwire Checks (5):**
1. `_check_network_in_airgap`
2. `_check_usb_in_coldroom`
3. `_check_external_model_violations`
4. `_check_suspicious_processes`
5. `_check_hardware_trust`

**Configurable Monitors (13):**
```python
monitor_lora: bool = True
monitor_thread: bool = True
monitor_cellular_security: bool = True
monitor_wimax: bool = False      # Disabled - obsolete
monitor_irda: bool = False       # Disabled - legacy
monitor_ant_plus: bool = True
monitor_dns_security: bool = True
monitor_arp_security: bool = True
monitor_wifi_security: bool = True
monitor_threat_intel: bool = True
monitor_file_integrity: bool = True
monitor_traffic_anomaly: bool = True
monitor_process_security: bool = True
```

### 5. API Commands (23)

| Category | Commands |
|----------|----------|
| Token (3) | create_token, revoke_token, list_tokens |
| Policy (4) | check_recall, check_tool, check_message, set_mode |
| Status (6) | status, rate_limit_status, get_health_stats, get_monitoring_summary, get_resource_stats, check_ollama_status |
| Log (2) | get_events, verify_log |
| Integration (3) | check_natlangchain, check_agentos, check_message |
| Reporting (5) | get_memory_stats, get_queue_stats, generate_report, get_raw_report, get_report_history |

### 6. Security Gates (38)

**By Category:**

| Category | Gates | Count |
|----------|-------|-------|
| Core | check_recall, check_tool, check_message | 3 |
| Cryptographic | verify_key_derivation, verify_merkle_proof, verify_cryptographic_signature, verify_zkp_proof | 4 |
| Semantic | classify_intent_semantics, detect_semantic_drift, detect_cross_language_injection, verify_llm_consensus | 4 |
| Economic | verify_stake_escrow, verify_stake_burned, verify_effort_proof, verify_w3c_credential | 4 |
| Cognitive | check_reflection_intensity, check_identity_mutation, check_agent_attestation | 3 |
| Contract | verify_contract_signature, verify_memory_not_revoked, check_contract_delegation_depth, verify_constitution_integrity | 4 |
| Execution | verify_execution_confidence, detect_political_activity, verify_sunset_deadline, prevent_posthumous_revocation | 4 |
| Dispute | check_counter_proposal_limit, verify_settlement_honors_constraints, check_dispute_class_mode_requirement | 3 |
| SIEM | verify_detection_rule_signature, audit_rule_state_change, correlate_siem_event | 3 |
| Rate Limit | check_entity_rate_limit | 1 |
| Consent | verify_memory_consent, verify_physical_token_presented | 2 |
| Middleware | initiate_ceremony, check_anomaly_score, get_graduated_permission | 3 |

### 7. Event Types (26)

| Category | Types |
|----------|-------|
| System (4) | MODE_CHANGE, DAEMON_START, DAEMON_STOP, OVERRIDE |
| Security (9) | VIOLATION, TRIPWIRE, POLICY_DECISION, RECALL_ATTEMPT, TOOL_REQUEST, BIOMETRIC_ATTEMPT, SECURITY_SCAN, CLOCK_JUMP, CLOCK_DRIFT |
| API (4) | API_REQUEST, MESSAGE_CHECK, HEALTH_CHECK, NTP_SYNC_LOST |
| Rate Limit (4) | RATE_LIMIT_TOKEN, RATE_LIMIT_GLOBAL, RATE_LIMIT_COMMAND, RATE_LIMIT_UNBLOCK |
| PII (3) | PII_DETECTED, PII_BLOCKED, PII_REDACTED |
| General (2) | ALERT, INFO |

---

## Performance Recommendations

### Current Architecture (Optimized)

The daemon uses several performance optimizations:

1. **Tiered Polling Intervals:**
   - Critical (1s): State monitor
   - Standard (5-10s): Memory, resources, enforcement
   - Background (60s): Health, integrity, dead-man

2. **Caching Strategy:**
   - Threat intel: 1-hour TTL, 10K max entries
   - Identity: 5-minute TTL
   - TPM PCRs: 5-second TTL

3. **Async Processing:**
   - Event logging is asynchronous
   - Background threads for non-critical monitors
   - Rate limiting prevents CPU spikes

4. **Configurable Monitors:**
   - Legacy monitors (WiMAX, IrDA) disabled by default
   - Each monitor can be individually toggled

### Resource Usage Estimate

| Component | CPU Impact | Memory | Notes |
|-----------|-----------|--------|-------|
| State Monitor | ~1% | ~10MB | 1Hz polling |
| Health Monitor | <0.1% | ~5MB | 60s interval |
| Memory Monitor | ~0.5% | ~20MB | 5s sampling, history |
| Resource Monitor | ~0.5% | ~15MB | 10s sampling, history |
| Event Logger | <0.1% | ~50MB | Async, hash chains |
| Tripwires | ~0.5% | ~5MB | Per-check evaluation |
| **Total** | **~3%** | **~105MB** | Normal operation |

### Tuning for High-Security Environments

For maximum monitoring without performance issues:

```ini
[daemon]
poll_interval = 1.0          # Keep at 1Hz for real-time

[health]
check_interval = 30.0        # Increase frequency
heartbeat_interval = 5.0     # More frequent heartbeats

[memory]
sample_interval = 2.0        # More frequent sampling
history_size = 1800          # 1 hour at 2s

[resource]
sample_interval = 5.0        # More frequent
history_size = 720           # 1 hour at 5s

[threat_intel]
cache_ttl = 1800            # 30 min (fresher data)
max_cache_size = 50000      # More entries

[monitors]
all_enabled = true          # Enable all monitors
```

### Tuning for Resource-Constrained Environments

```ini
[daemon]
poll_interval = 5.0          # Reduce to 5Hz

[health]
check_interval = 120.0       # 2 minutes
heartbeat_interval = 30.0    # 30 seconds

[memory]
sample_interval = 30.0       # Less frequent
history_size = 120           # 1 hour at 30s

[monitors]
monitor_wimax = false
monitor_irda = false
monitor_ant_plus = false
monitor_traffic_anomaly = false  # Most CPU-intensive
```

---

## Module Watch Capability Matrix

All modules can be monitored with the following granularity:

| Module | Real-time | Historical | Alerting | Audit |
|--------|-----------|------------|----------|-------|
| Policy Engine | ✅ | ✅ | ✅ | ✅ |
| State Monitor | ✅ | ✅ | ✅ | ✅ |
| Tripwires | ✅ | ✅ | ✅ | ✅ |
| Event Logger | ✅ | ✅ | ✅ | ✅ |
| Health Monitor | ✅ | ✅ | ✅ | ✅ |
| Memory Monitor | ✅ | ✅ | ✅ | ✅ |
| Resource Monitor | ✅ | ✅ | ✅ | ✅ |
| API Layer | ✅ | ✅ | ✅ | ✅ |
| Enforcement | ✅ | ✅ | ✅ | ✅ |
| Security Gates | ✅ | ✅ | ✅ | ✅ |
| Integrations | ✅ | ✅ | ✅ | ✅ |

**Conclusion:** All 47 monitoring points can be watched continuously at 1Hz without significant performance impact (<3% CPU, ~105MB RAM on a modern system).

---

*Generated: 2026-01-02*
*Daemon Version: 0.1.0-alpha*
