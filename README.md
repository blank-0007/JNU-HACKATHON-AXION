# Decentralized Runtime Integrity Engine for Remote Agents

A software agent running on a (remote) machine periodically measures the protected
service's **binary**, **configuration** and **runtime memory**. It **signs** each measurement
with its own key and **anchors** it on a local blockchain. The smart contract verifies the
signature and compares each component with its golden reference. A separate **verifier**
dashboard re-checks everything independently and detects tampering live.

```
 ┌────────────── agent container (the "remote machine") ─────────────┐
 │ every 2s:  SHA-256(binary) · SHA-256(config) · SHA-256(memory)     │
 │            sign(contract, chain, seq, hashes, cost) with agent key │──┐ signed
 └───────────────────────────────────────────────────────────────────┘  │ measurement
 ┌────────────── chain container: IntegrityLedger.sol ───────────────┐  │ (relayer pays gas)
 │ ecrecover(signature) == enrolled agent?  seq strictly increasing?  │◄─┘
 │ compare with golden references → adopt if approved, else ALERT     │
 └───────────────────────────────────────────────────────────────────┘
 ┌────────────── verifier container: dashboard :8501 ────────────────┐
 │ reads the ledger · re-verifies signatures off-chain · heartbeat    │
 └───────────────────────────────────────────────────────────────────┘
```

| State | Condition |
|---|---|
| 🟢 **Verified** | all three components match their on-chain reference |
| 🔵 **Authorized update** | a component changed, and the developer approved exactly that component on-chain beforehand. The contract adopts the new reference and consumes the approval |
| 🔴 **Unauthorized modification** | a component changed without approval, so a `TamperDetected` alert is written on-chain |
| 🔴 **Agent silent** | no valid signed measurement for 7 seconds: a killed or hijacked agent counts as compromised |

## Run it

Needs Docker (Docker Desktop, or `colima start`).

```bash
./demo.sh
```

Open http://localhost:8501. The first build takes a few minutes, and Ctrl-C stops everything.
Equivalent: `docker compose up --build`.

## What is measured

| Component | What | Attack button |
|---|---|---|
| **Binary** | `target_system/bin/checkout-service` (a static C binary built in the image) + the agent's own code | **Replace binary**: appends a payload to the executable |
| **Config** | `target_system/config.json` | **Tamper config**: redirects the payment gateway, disables MFA, adds a backdoor admin |
| **Memory** | the agent's in-RAM security policy + bytecode of its critical functions (`authorize_payment`, the measurement and signing code) | **Patch memory**: rewrites the policy in RAM and hooks `authorize_payment` to approve everything; the files on disk are unchanged |

The memory measurement hashes the objects the process is actually executing, looked up live,
so a monkey-patched function is caught even though every file on disk still hashes clean.

## Demo script (about 2 minutes)

1. **Green.** "The agent sends a signed measurement every 2 seconds, about 1.5 ms each. The contract
   verifies the signature on-chain." Point at the *Signed attestation* card.
2. **Tamper config.** Config turns red, the diff shows the backdoor, and the alert is recorded on-chain.
3. **Approve update while red.** The contract itself refuses: an approval can't launder an attack.
4. **Reset**, then **Patch memory.** Disk is untouched, but memory turns red. This is the highlight.
5. **Reset**, then **Approve update.** The developer approves *config only* on-chain, the release lands,
   the reference is adopted, and the dashboard turns blue. The approval is one-shot and expires after 60 seconds.
6. **Kill the agent** in a terminal: `docker compose stop agent`. The dashboard shows *Agent silent*
   within 7 seconds. Bring it back with `docker compose start agent`.
7. **Bonus.** Edit `target_system/config.json` in your IDE, or run
   `printf 'x' >> target_system/bin/checkout-service`. Both turn red within 2 seconds, straight from the host.

Useful terminal view during the demo: `docker compose logs -f agent`.

## Security design (for judges' questions)

- **Signed measurements.** The agent's secp256k1 key is created on first boot and stored on a
  volume mounted **only** in the agent container. The contract recovers the signer with `ecrecover`.
  A separate relayer account pays gas, so being the transaction sender proves nothing: the signature does.
- **Replay protection.** A strictly increasing `seq`, bound together with the contract address and chain id.
- **Scoped, one-shot, expiring approvals.** `authorizeUpdate(mask)` covers specific components for
  one measurement, within 60 seconds. It is refused while the system is tampered. A release that
  touches config does not bless a simultaneous binary change.
- **Tamper evidence.** Every enrollment, approval, reference update and alert is an on-chain event.
  The dashboard's audit trail is read from those logs, not from a local database.
- **Independent verifier.** The dashboard re-verifies every signature off-chain and treats a missing
  heartbeat as compromise.
- **Trust on first measurement.** Enrollment adopts the first signed measurement as golden, so the
  verifier resets the target to a known-good state before enrolling.

**Demo shortcuts, and what production would do:**
- The dashboard's attack buttons reach the agent through a demo-only control folder. `DEMO_CONTROLS=0` disables it.
- Hardhat's unlocked accounts play the developer and relayer.
- The golden reference is trust-on-first-use. In production it would come from a signed build manifest.

## Stretch goals, and how this extends

- **TPM/TEE attestation.** Replace the software key with a TPM-resident key and add PCR quotes to the
  signed payload (a software TPM on Linux would do for development). The contract interface stays the same.
- **Low-overhead measurement.** Measurement cost is already reported on-chain with every heartbeat
  (about 1–2 ms per cycle). Next steps: hash only on file-change notifications, and use incremental hashing for large binaries.
- **Secret protection.** Keep the signing key in the macOS Keychain, an HSM or a TPM instead of a file.

## Files

| Path | Role |
|---|---|
| `contracts/IntegrityLedger.sol` | on-chain verifier: signature check, references, scoped approvals, alerts |
| `agent/agent.py` | measures, signs, submits every 2s |
| `agent/checkout_service.c` | the protected workload binary |
| `verifier/deploy.py` | deploys the ledger and enrolls the agent's public key |
| `verifier/app.py` | Streamlit verifier dashboard |
| `verifier/ledger.py` | web3.py reads/writes, off-chain signature re-verification |
| `verifier/target.py` | attack and restore scenarios on the shared files |
| `docker-compose.yml` | chain + agent + verifier |
