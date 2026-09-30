"""Deploy IntegrityLedger and enroll the agent's public key (runs on every verifier start).

1. wait for the chain and for the agent to publish its public address
2. reset the target to a known-good state (baseline config, pristine binary, clean memory)
3. deploy the contract with the developer account as owner
4. registerAgent(agent address): the agent's next signed measurement becomes the golden reference
"""
import json
import time

from web3 import Web3

import target
from ledger import DEPLOYMENT_FILE, RPC_URL, SHARED

ARTIFACT = SHARED / "IntegrityLedger.json"  # copied here by the chain container
AGENT_INFO = SHARED / "agent.json"          # written by the agent on boot


def wait_for(what, check, timeout=120):
    deadline = time.time() + timeout
    while not check():
        if time.time() > deadline:
            raise SystemExit(f"Timed out waiting for {what}")
        time.sleep(0.5)


def main():
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    wait_for("the chain", lambda: w3.is_connected())
    wait_for("the contract artifact", ARTIFACT.exists)
    wait_for("the agent's public key", AGENT_INFO.exists)

    artifact = json.loads(ARTIFACT.read_text())
    agent = Web3.to_checksum_address(json.loads(AGENT_INFO.read_text())["address"])
    dev, relayer = w3.eth.accounts[0], w3.eth.accounts[1]  # unlocked Hardhat accounts

    # Known-good starting point, so enrollment captures a clean system.
    target.write_baseline()
    target.save_snapshot()
    target.send_control("restore_binary")
    target.send_control("restore_memory")

    factory = w3.eth.contract(abi=artifact["abi"], bytecode=artifact["bytecode"])
    receipt = w3.eth.wait_for_transaction_receipt(factory.constructor().transact({"from": dev}))
    ledger = w3.eth.contract(address=receipt.contractAddress, abi=artifact["abi"])

    DEPLOYMENT_FILE.write_text(json.dumps({
        "address": receipt.contractAddress,
        "deployBlock": receipt.blockNumber,
        "chainId": w3.eth.chain_id,
        "dev": dev,
        "relayer": relayer,
        "agent": agent,
        "abi": artifact["abi"],
    }, indent=2))
    # The agent handles control requests before each measurement, so the restores above
    # always land before the enrollment measurement.
    w3.eth.wait_for_transaction_receipt(ledger.functions.registerAgent(agent).transact({"from": dev}))

    print(f"IntegrityLedger at {receipt.contractAddress} (block {receipt.blockNumber}, chain {w3.eth.chain_id})")
    print(f"Enrolled agent key {agent}")


if __name__ == "__main__":
    main()
