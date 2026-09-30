"""Integrity agent: runs next to the protected service on the (remote) machine.

Every MEASURE_INTERVAL seconds it:
  1. measures three components with SHA-256
       BINARY  the service executable + this agent's own code
       CONFIG  the service configuration file
       MEMORY  the security policy and critical code objects live in this process's RAM
  2. signs (contract, chain, seq, hashes, cost) with its private key (ECDSA secp256k1)
  3. submits the signed measurement to IntegrityLedger, which verifies the signature
     on-chain and compares each hash with the golden reference.

The private key never leaves this container (it lives on the agent-only /secrets volume).
Gas is paid by a separate relayer account, so the tx sender proves nothing: the signature does.
"""
import copy
import hashlib
import json
import os
import shutil
import time
from pathlib import Path

from eth_account import Account
from eth_account.messages import encode_defunct
from web3 import Web3
from web3.logs import DISCARD

RPC_URL = os.environ.get("RPC_URL", "http://chain:8545")
INTERVAL = float(os.environ.get("MEASURE_INTERVAL", "2"))
DEMO_CONTROLS = os.environ.get("DEMO_CONTROLS", "1") == "1"

TARGET = Path("/target")
CONFIG_FILE = TARGET / "config.json"
SERVICE_BIN = TARGET / "bin" / "checkout-service"
PRISTINE_BIN = Path("/opt/pristine/checkout-service")  # baked into the image at build time
SHARED = Path("/shared")
DEPLOYMENT = SHARED / "deployment.json"
AGENT_INFO = SHARED / "agent.json"
CONTROL_DIR = SHARED / "control"
KEY_FILE = Path("/secrets/agent.key")
AGENT_CODE = sorted(Path(__file__).resolve().parent.glob("*.py"))

# ----------------------------------------------------------- protected runtime state
# This is what the MEMORY measurement covers: the policy the service enforces and the
# code that enforces it, as they exist in RAM right now (not as they are on disk).
SECURITY_POLICY = {
    "max_transaction": 10000,
    "allowed_gateways": ["payments.internal.example.com"],
    "require_mfa": True,
}
_BASELINE_POLICY = copy.deepcopy(SECURITY_POLICY)


def authorize_payment(amount, gateway):
    """The enforcement hook a runtime attack would want to patch."""
    return amount <= SECURITY_POLICY["max_transaction"] and gateway in SECURITY_POLICY["allowed_gateways"]


_ORIGINAL_AUTHORIZE = authorize_payment
CRITICAL_FUNCTIONS = ("authorize_payment", "measure_binary", "measure_config", "measure_memory", "sign_measurement")


# ------------------------------------------------------------------- measurements
def _file_digest(path):
    try:
        return hashlib.sha256(path.read_bytes()).digest()
    except OSError:
        return b"missing"


def measure_binary():
    h = hashlib.sha256()
    for path in (SERVICE_BIN, *AGENT_CODE):
        h.update(path.name.encode())
        h.update(_file_digest(path))
    return h.digest()


def measure_config():
    try:
        return hashlib.sha256(CONFIG_FILE.read_bytes()).digest()
    except OSError:
        return hashlib.sha256(b"missing").digest()


def _code_fingerprint(code):
    """Deterministic bytes for a code object (recursing into nested code, no memory addresses)."""
    parts = [code.co_code, " ".join(code.co_names).encode()]
    for const in code.co_consts:
        parts.append(_code_fingerprint(const) if hasattr(const, "co_code") else repr(const).encode())
    return b"|".join(parts)


def measure_memory():
    h = hashlib.sha256(json.dumps(SECURITY_POLICY, sort_keys=True).encode())
    for name in CRITICAL_FUNCTIONS:
        fn = globals()[name]  # looked up live, so a monkey-patched replacement is what gets hashed
        h.update(name.encode())
        h.update(_code_fingerprint(fn.__code__))
    return h.digest()


def sign_measurement(account, contract_address, chain_id, seq, binary, config, memory, cost):
    digest = Web3.solidity_keccak(
        ["address", "uint256", "uint64", "bytes32", "bytes32", "bytes32", "uint32"],
        [contract_address, chain_id, seq, binary, config, memory, cost])
    return account.sign_message(encode_defunct(primitive=digest)).signature


# ---------------------------------------------------------------------- identity
def load_or_create_key():
    """Agent identity: a secp256k1 key created on first boot, readable only by the agent."""
    KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    if KEY_FILE.exists():
        return Account.from_key(KEY_FILE.read_text().strip())
    account = Account.create()
    fd = os.open(KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, account.key.hex().encode())
    os.close(fd)
    return account


def install_service_binary(only_if_missing=False):
    if only_if_missing and SERVICE_BIN.exists():
        return  # never silently "heal" a tampered binary on restart: it must get reported
    SERVICE_BIN.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(PRISTINE_BIN, SERVICE_BIN)
    SERVICE_BIN.chmod(0o755)


# ------------------------------------------------------------- demo attack hooks
# DEMO ONLY: lets the dashboard's buttons simulate an in-memory compromise of this
# process and roll it back. A production agent has no such channel.
def handle_demo_controls():
    global authorize_payment
    if not DEMO_CONTROLS or not CONTROL_DIR.exists():
        return
    for request in sorted(CONTROL_DIR.iterdir()):
        request.unlink(missing_ok=True)
        if request.name == "tamper_memory":
            SECURITY_POLICY["max_transaction"] = 10 ** 9
            SECURITY_POLICY["allowed_gateways"].append("payments-verify.attacker.net")
            authorize_payment = lambda amount, gateway: True  # noqa: E731  hooked: approves everything
            log("demo: simulated in-memory compromise (policy rewritten, authorize_payment hooked)")
        elif request.name == "restore_memory":
            SECURITY_POLICY.clear()
            SECURITY_POLICY.update(copy.deepcopy(_BASELINE_POLICY))
            authorize_payment = _ORIGINAL_AUTHORIZE
            log("demo: memory state restored")
        elif request.name == "restore_binary":
            install_service_binary()
            log("demo: service binary reinstalled from the pristine image copy")


# --------------------------------------------------------------------- main loop
def log(msg):
    print(time.strftime("%H:%M:%S"), msg, flush=True)


def load_contract(w3):
    dep = json.loads(DEPLOYMENT.read_text())
    if len(w3.eth.get_code(dep["address"])) == 0:
        return None, None
    return w3.eth.contract(address=dep["address"], abi=dep["abi"]), dep


def main():
    account = load_or_create_key()
    AGENT_INFO.write_text(json.dumps({"address": account.address}))
    install_service_binary(only_if_missing=True)
    log(f"agent key {account.address} (private key stays in {KEY_FILE.parent})")

    w3 = Web3(Web3.HTTPProvider(RPC_URL, request_kwargs={"timeout": 5}))
    contract = dep = None
    dep_stamp = None
    waiting_logged = False

    while True:
        started = time.monotonic()
        try:
            handle_demo_controls()

            stamp = DEPLOYMENT.stat().st_mtime if DEPLOYMENT.exists() else None
            if stamp != dep_stamp:
                contract, dep = load_contract(w3) if stamp else (None, None)
                dep_stamp = stamp if contract else None
                if contract:
                    log(f"ledger at {dep['address']} (chain {w3.eth.chain_id})")
                    waiting_logged = False

            if contract is None or contract.functions.agent().call() != account.address:
                if not waiting_logged:
                    log("waiting for the ledger to register this agent key…")
                    waiting_logged = True
            else:
                handle_demo_controls()  # again, right before measuring (closes an enrollment race)
                t0 = time.perf_counter()
                binary, config, memory = measure_binary(), measure_config(), measure_memory()
                cost = int((time.perf_counter() - t0) * 1e6)

                seq = time.time_ns() // 1_000_000  # ms timestamp: strictly increasing, no state needed
                chain_id = w3.eth.chain_id
                sig = sign_measurement(account, contract.address, chain_id, seq, binary, config, memory, cost)
                tx = contract.functions.submitMeasurement(seq, binary, config, memory, cost, sig) \
                    .transact({"from": dep["relayer"]})
                receipt = w3.eth.wait_for_transaction_receipt(tx, timeout=10)

                mismatch = contract.events.Measured().process_receipt(receipt, errors=DISCARD)[0]["args"]["mismatch"]
                marks = " ".join(f"{name} {'✗' if mismatch & bit else '✓'}"
                                 for name, bit in (("binary", 1), ("config", 2), ("memory", 4)))
                verdict = "TAMPER" if mismatch else "ok"
                log(f"#{seq} {marks}  {cost / 1000:.2f} ms  block {receipt.blockNumber}  {verdict}")
        except Exception as exc:  # chain restarting, redeploy in progress, etc.
            log(f"error: {type(exc).__name__}: {exc}")
            contract, dep_stamp = None, None
        time.sleep(max(0.0, INTERVAL - (time.monotonic() - started)))


if __name__ == "__main__":
    main()
