# boundary-daemon-
boundary-daemon/ ├─ daemon/ │ ├─ state_monitor.py # Network, hardware, process sensing │ ├─ policy_engine.py # Mode × signal × request │ └─ tripwires.py │ ├─ api/ │ └─ boundary.sock # Local-only command socket │ ├─ logs/ │ └─ boundary_chain.log # Immutable event log └─ README.md
