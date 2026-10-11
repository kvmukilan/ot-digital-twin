# Deployment and runtime checks

Build with `python -m build`, install the resulting wheel in a fresh environment, and run `ot-twin --version` and `ot-twin list-registers` outside the source checkout. The wheel includes the MITRE ICS catalog and requires pymodbus 3.10 or 3.11, matching the device-context/client APIs used by this code.

Set `OT_TWIN_DATA_DIR` to a writable persistent directory, with optional `HISTORIAN_DB_PATH`. Packaged static technique data stays separate from mutable historian data. Run `ot-twin start-plc --host 127.0.0.1 --port 5020`; the server now reports readiness after a successful bind, propagates bind failure, and shuts down both the listener and simulation on cancellation.

CI installs the wheel outside the checkout and tests actual loopback Modbus reads, register defaults, occupied ports, and port release. Run `pytest tests -q` before rollout. Use a private lab network for remote PLC access; Modbus itself has no authentication. Keep historian backups and the previous wheel for rollback.
