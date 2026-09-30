"""Web3.py bridge from the verifier to IntegrityLedger."""
import json
import os
from dataclasses import dataclass
from pathlib import Path

from eth_account import Account
from eth_account.messages import encode_defunct
from web3 import Web3

SHARED = Path("/shared")
DEPLOYMENT_FILE = SHARED / "deployment.json"  # written by deploy.py
RPC_URL = os.environ.get("RPC_URL", "http://chain:8545")

COMPONENTS = (("binary", 1), ("config", 2), ("memory", 4))


class ChainOffline(Exception):
    pass


class NotDeployed(Exception):
    pass


def mask_names(mask):
    return [name for name, bit in COMPONENTS if mask & bit]


@dataclass
class Measurement:
    seq: int
    hashes: tuple        # (binary, config, memory) as 0x-hex
    mismatch: int
    cost_us: int
    signature: bytes
    block: int
    timestamp: int
    sender: str          # relayer that paid gas (not trusted)


@dataclass
class TrailEntry:
    kind: str            # "registered" | "authorized" | "updated" | "tamper"
    block: int
    log_index: int
    timestamp: int
    mask: int
    hashes: tuple
    by: str


class Ledger:
    def __init__(self, rpc_url=RPC_URL):
        self.w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 3}))
        if not self.w3.is_connected():
            raise ChainOffline(rpc_url)
        if not DEPLOYMENT_FILE.exists():
            raise NotDeployed("deployment.json missing")
        dep = json.loads(DEPLOYMENT_FILE.read_text())
        if len(self.w3.eth.get_code(dep["address"])) == 0:
            raise NotDeployed("no contract code at " + dep["address"])

        self.address = dep["address"]
        self.contract = self.w3.eth.contract(address=dep["address"], abi=dep["abi"])
        self.dev = dep["dev"]
        self.relayer = dep["relayer"]
        self.agent = dep["agent"]
        self.deploy_block = dep["deployBlock"]
        self.chain_id = self.w3.eth.chain_id

    # ------------------------------------------------------------------ reads
    def references(self):
        return tuple(Web3.to_hex(h) for h in self.contract.functions.getReferences().call())

    def approved_mask(self):
        return self.contract.functions.approvedMask().call()

    def recent_measurements(self, window=120):
        """Measured events from the last `window` blocks, oldest first."""
        start = max(self.deploy_block, self.w3.eth.block_number - window)
        out = []
        for log in self.contract.events.Measured.get_logs(from_block=start):
            a = log["args"]
            out.append(Measurement(
                seq=a["seq"],
                hashes=tuple(Web3.to_hex(a[k]) for k in ("binaryHash", "configHash", "memoryHash")),
                mismatch=a["mismatch"], cost_us=a["costMicros"], signature=bytes(a["signature"]),
                block=log["blockNumber"], timestamp=a["timestamp"], sender=None))
        return out

    def trail(self):
        """Every notable (non-heartbeat) event since deployment, oldest first."""
        ev = self.contract.events
        out = []
        for log in ev.AgentRegistered.get_logs(from_block=self.deploy_block):
            out.append(self._entry("registered", log, 0, (), log["args"]["agent"]))
        for log in ev.UpdateAuthorized.get_logs(from_block=self.deploy_block):
            out.append(self._entry("authorized", log, log["args"]["mask"], (), log["args"]["by"]))
        for kind, event in (("updated", ev.ReferenceUpdated), ("tamper", ev.TamperDetected)):
            for log in event.get_logs(from_block=self.deploy_block):
                a = log["args"]
                hashes = tuple(Web3.to_hex(a[k]) for k in ("binaryHash", "configHash", "memoryHash"))
                out.append(self._entry(kind, log, a["mask"], hashes, self.agent))
        out.sort(key=lambda e: (e.block, e.log_index))
        return out

    @staticmethod
    def _entry(kind, log, mask, hashes, by):
        return TrailEntry(kind, log["blockNumber"], log["logIndex"], log["args"]["timestamp"], mask, hashes, by)

    # ------------------------------------------------- off-chain re-verification
    def signer_of(self, m):
        """Independently recover who signed a measurement (the contract already checked it too)."""
        digest = Web3.solidity_keccak(
            ["address", "uint256", "uint64", "bytes32", "bytes32", "bytes32", "uint32"],
            [self.address, self.chain_id, m.seq, *m.hashes, m.cost_us])
        return Account.recover_message(encode_defunct(primitive=digest), signature=m.signature)

    # ----------------------------------------------------------------- writes
    def authorize_update(self, mask):
        tx = self.contract.functions.authorizeUpdate(mask).transact({"from": self.dev})
        return self.w3.eth.wait_for_transaction_receipt(tx, timeout=10)

    def label(self, address):
        return {self.dev: "Dev", self.agent: "Agent-01", self.relayer: "Relayer"}.get(address, address[:8] + "…")
