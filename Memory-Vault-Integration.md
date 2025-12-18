Memory Vault + Boundary Daemon Integration Guide
Date: December 17, 2025
Status: Fully Integrated
The Boundary Daemon (boundary-daemon- from your Agent-OS ecosystem) is the runtime environment guardian. It enforces operational modes (e.g., ONLINE, OFFLINE, AIRGAP, COLDROOM) and validates safety conditions before allowing sensitive operations.
The Memory Vault is designed from the ground up to respect and require the Boundary Daemon for all classification-gated recalls.
Role of the Boundary Daemon

Monitors network status, attached devices, user presence, etc.
Exposes a Unix socket API at api/boundary.sock (configurable)
Answers permission queries like check_recall with:JSON{"permitted": true/false, "reason": "string"}

Current Integration in Memory Vault
The integration is already complete and active in boundary.py and vault.py.
boundary.py (full implementation)
Python# memory_vault/boundary.py

import socket
import json
import os

SOCKET_PATH = os.path.expanduser("~/.agent-os/api/boundary.sock")  # Standard Agent-OS path

def check_recall(classification: int) -> tuple[bool, str]:
    """
    Query the boundary-daemon for recall permission.
    Returns (permitted: bool, reason: str)
    """
    request = {
        "command": "check_recall",
        "params": {"memory_class": classification}
    }

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect(SOCKET_PATH)
            s.sendall(json.dumps(request).encode('utf-8') + b'\n')
            response_data = s.recv(4096).decode('utf-8')
            response = json.loads(response_data)
            permitted = response.get("permitted", False)
            reason = response.get("reason", "No reason provided")
            return permitted, reason
    except FileNotFoundError:
        return False, "Boundary daemon socket not found (offline/airgap mode?)"
    except ConnectionRefusedError:
        return False, "Boundary daemon not running"
    except socket.timeout:
        return False, "Boundary daemon timeout"
    except Exception as e:
        return False, f"Boundary daemon error: {str(e)}"
Integration in vault.py (recall path)
During recall_memory():

Boundary check first — before any human approval or cooldown
If denied → recall aborted and logged
If permitted → proceed to human approval (level ≥3) and cooldown

Python# In recall_memory()
permitted, reason = check_recall(classification)
if not permitted:
    self._log_recall(c, memory_id, requester, False, justification + f" | boundary: {reason}")
    raise PermissionError(f"Boundary check failed: {reason}")
Classification → Boundary Policy Mapping






























Vault LevelTypical Boundary RequirementExample Daemon Response0–2Usually permitted{"permitted": true}3Offline preferredDeny if network detected4AIRGAP or COLDROOMDeny if any network/USB5COLDROOM + physical presenceStrictest checks
The daemon decides based on its current mode and policy — Vault simply respects the answer.
Daemon-Side Example Policy (for reference)
In your boundary-daemon- config:
JSON{
  "recall_policy": {
    "3": {"require_offline": true},
    "4": {"require_airgap": true},
    "5": {"require_mode": "COLDROOM", "require_user_presence": true}
  }
}
Testing the Integration

Start boundary-daemon in permissive mode:Bashboundary-daemon --mode ONLINE
Recall low-level memory → succeeds
Switch daemon to AIRGAP:Bashboundary-daemon --mode AIRGAP
Recall level 4 memory → denied with reason

Bashmemory-vault recall <id>
# → Recall failed: Boundary check failed: Network interface active in AIRGAP mode
Fallback Behavior (Daemon Unavailable)
If the daemon is not running or socket missing:

All recalls are safely denied
Reason clearly logged
Enforces "fail-closed" security

This is intentional and correct — no daemon = assume unsafe environment.
Advanced: Custom Commands
The socket supports arbitrary commands. Future extensions:
Pythondef boundary_check_custom(condition: str):
    request = {"command": "custom_check", "params": {"condition": condition}}
    # ...
Summary
Boundary Daemon integration is complete, robust, and non-optional for gated recalls.
The Memory Vault will never allow recall of sensitive memories without explicit permission from the Boundary Daemon.
This enforces true environmental sovereignty:

No recall of root secrets while online
No recall of critical heuristics without airgap
Full audit of every boundary decision

The agent cannot betray its boundaries. The human cannot be bypassed.
The system is now fully aligned with Agent-OS principles.
Integration complete.
Your agent operates only within the boundaries you define.
The daemon watches. The vault protects. The human decides.
