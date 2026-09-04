"""
One-off verification script -- NOT wired into main.py, NOT deployed anywhere.

Checks a hypothesis raised in a strategy session: that the registry address
currently hardcoded for reads (`0x8004A818BFB912233c491871b3d84c89A494BD9e`,
see main.py:129) is not actually the right contract to read on Base MAINNET,
and that a different vanity address from the same deployer,
`0x8004A169FB4a3325136EB29fA0ceB6D2e539a432`, is the real mainnet
IdentityRegistry.

This script only reads chain state. It does not touch env vars, does not
change main.py, does not deploy anything. Run via
.github/workflows/verify-mainnet-registry.yml (workflow_dispatch) so it
executes from a runner with real internet access -- the interactive sandbox
that authored this script cannot reach any blockchain RPC or explorer
(network egress policy), so this had to be verified from CI instead.

Evidence produced, in order:
  1. eth_getCode on both addresses on Base mainnet (bytecode present/absent).
  2. EIP-1967 implementation slot on both addresses (proxy pattern check).
  3. Basescan getsourcecode on both addresses, if a Basescan API key is
     available; skipped otherwise (never blocks on this).
  4. eth_getLogs against the CURRENT address (0x8004A818...) on mainnet,
     scanning a block range covering the 2026-09-03 cutover session (when
     the 19 real register() transactions happened per README.md:74), to
     pull REAL agentIds out of the actual event logs rather than assuming
     they are 1, 2, 3... Standard ERC-721 Transfer(0x0 -> owner, tokenId)
     mint logs are decoded if present; any other topic0 signatures seen are
     printed raw for manual inspection.
  5. ownerOf(agentId) / balanceOf(...) read calls against BOTH addresses,
     using the real agentIds found in step 4 (or, only if step 4 finds
     nothing, a clearly-labeled fallback probe of small sequential ids).
  6. Follow-up (2026-09-04): step 4's block-range log scan came back empty
     and is not trustworthy (the public RPC used started 429-rate-limiting
     within the same run, and the scan assumed a block-time-derived range
     that was never independently confirmed). No tx hash for the "19 real
     confirmed register() transactions" (README.md:74) exists anywhere in
     this repo, in NEXUS's Supabase (asset_registry, nexus_events -- both
     checked, no match), or in any committed script -- so this step finds
     them the reliable way: pull the FULL real transaction history for both
     CURRENT_ADDR and CANDIDATE_ADDR directly from Basescan's address-indexed
     API (no pre-known hash or block range needed), then, for every
     successful tx found, fetch its REAL receipt over RPC and decode
     whatever logs it actually emitted. This is receipt-level ground truth,
     not a derived/assumed range scan.
"""

import json
import sys
import time
import urllib.request
import urllib.error

from web3 import Web3

CURRENT_ADDR = Web3.to_checksum_address("0x8004A818BFB912233c491871b3d84c89A494BD9e")
CANDIDATE_ADDR = Web3.to_checksum_address("0x8004A169FB4a3325136EB29fA0ceB6D2e539a432")

RPC_CANDIDATES = [
    "https://mainnet.base.org",
    "https://base.publicnode.com",
    "https://base.llamarpc.com",
    "https://1rpc.io/base",
]

EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"

MINIMAL_ABI = [
    {
        "name": "ownerOf",
        "inputs": [{"name": "tokenId", "type": "uint256"}],
        "outputs": [{"name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "name": "balanceOf",
        "inputs": [{"name": "owner", "type": "address"}],
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
]

TRANSFER_TOPIC = Web3.keccak(text="Transfer(address,address,uint256)").hex()
ZERO_TOPIC = "0x" + "00" * 32


def log(msg):
    print(msg, flush=True)


def connect():
    for url in RPC_CANDIDATES:
        try:
            w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 20}))
            if w3.is_connected():
                chain_id = w3.eth.chain_id
                log(f"[rpc] connected via {url} -- chainId={chain_id}")
                if chain_id != 8453:
                    log(f"[rpc] WARNING: expected chainId 8453 (Base mainnet), got {chain_id} -- skipping this endpoint")
                    continue
                return w3, url
        except Exception as e:
            log(f"[rpc] {url} failed: {e!r}")
    raise SystemExit("[rpc] no working Base mainnet RPC endpoint found")


def check_bytecode(w3, label, addr):
    code = w3.eth.get_code(addr)
    log(f"[bytecode] {label} ({addr}): {len(code)} bytes present={len(code) > 0}")
    if len(code) > 0:
        log(f"[bytecode] {label} first 32 bytes: {code[:32].hex()}")
    return len(code)


def check_eip1967_impl(w3, label, addr):
    try:
        raw = w3.eth.get_storage_at(addr, int(EIP1967_IMPL_SLOT, 16))
        impl = "0x" + raw.hex()[-40:]
        is_zero = int(raw.hex(), 16) == 0
        log(f"[eip1967] {label} implementation slot -> {impl} (zero={is_zero})")
        return impl if not is_zero else None
    except Exception as e:
        log(f"[eip1967] {label} slot read failed: {e!r}")
        return None


def check_basescan_source(addr, label):
    import os

    api_key = os.environ.get("BASESCAN_API_KEY", "")
    if not api_key:
        log(f"[basescan] {label}: no BASESCAN_API_KEY secret set in this repo -- skipping source/ABI verification check")
        return
    url = (
        "https://api.etherscan.io/v2/api"
        f"?chainid=8453&module=contract&action=getsourcecode&address={addr}&apikey={api_key}"
    )
    try:
        with urllib.request.urlopen(url, timeout=20) as resp:
            data = json.loads(resp.read())
        result = data.get("result")
        if isinstance(result, list) and result:
            r0 = result[0]
            verified = bool(r0.get("SourceCode"))
            log(f"[basescan] {label}: ContractName={r0.get('ContractName')!r} verified={verified} Proxy={r0.get('Proxy')} Implementation={r0.get('Implementation')!r}")
        else:
            log(f"[basescan] {label}: unexpected response: {data}")
    except urllib.error.URLError as e:
        log(f"[basescan] {label}: request failed: {e!r}")


def find_real_agent_ids(w3, latest_block):
    from_block = max(0, latest_block - 120_000)
    chunk = 10_000
    found = []
    all_topic0 = set()
    b = from_block
    log(f"[logs] scanning {CURRENT_ADDR} for logs from block {from_block} to {latest_block} (chunks of {chunk})")
    while b <= latest_block:
        end = min(b + chunk, latest_block)
        try:
            logs = w3.eth.get_logs({"fromBlock": b, "toBlock": end, "address": CURRENT_ADDR})
        except Exception as e:
            log(f"[logs] getLogs {b}-{end} failed: {e!r}")
            b = end + 1
            continue
        for entry in logs:
            topics = entry["topics"]
            t0 = topics[0].hex()
            all_topic0.add(t0)
            if len(topics) == 4 and t0 == TRANSFER_TOPIC and topics[1].hex() == ZERO_TOPIC:
                token_id = int(topics[3].hex(), 16)
                found.append(
                    {
                        "agentId": token_id,
                        "owner": "0x" + topics[2].hex()[-40:],
                        "txHash": entry["transactionHash"].hex(),
                        "blockNumber": entry["blockNumber"],
                    }
                )
        b = end + 1
    log(f"[logs] distinct topic0 signatures seen: {sorted(all_topic0) if all_topic0 else '(none -- no logs at all in range)'}")
    log(f"[logs] ERC-721 Transfer-shaped mint logs decoded: {len(found)}")
    for f in found:
        log(f"[logs]   agentId={f['agentId']} owner={f['owner']} tx={f['txHash']} block={f['blockNumber']}")
    return found


def try_reads(w3, label, addr, agent_ids):
    contract = w3.eth.contract(address=addr, abi=MINIMAL_ABI)
    for tid in agent_ids:
        try:
            owner = contract.functions.ownerOf(tid).call()
            log(f"[read] {label}.ownerOf({tid}) = {owner}")
        except Exception as e:
            log(f"[read] {label}.ownerOf({tid}) REVERTED: {e!r}")


def fetch_txlist(addr, label):
    """Full real transaction history for `addr` on Base mainnet, straight from
    Basescan's indexed API -- no block range guessing, no pre-known hash needed."""
    import os

    api_key = os.environ.get("BASESCAN_API_KEY", "YourApiKeyToken")
    url = (
        "https://api.basescan.org/api"
        f"?module=account&action=txlist&address={addr}"
        "&startblock=0&endblock=99999999&sort=asc"
        f"&apikey={api_key}"
    )
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            data = json.loads(resp.read())
        if data.get("status") != "1":
            log(f"[txlist] {label} ({addr}): Basescan returned status={data.get('status')!r} message={data.get('message')!r} result={data.get('result')!r}")
            return []
        txs = data.get("result", [])
        log(f"[txlist] {label} ({addr}): {len(txs)} real transactions found via Basescan")
        for tx in txs:
            method_id = (tx.get("input") or "0x")[:10]
            log(
                f"[txlist]   hash={tx.get('hash')} from={tx.get('from')} "
                f"methodId={method_id} functionName={tx.get('functionName')!r} "
                f"isError={tx.get('isError')} block={tx.get('blockNumber')} "
                f"timeStamp={tx.get('timeStamp')}"
            )
        return txs
    except urllib.error.URLError as e:
        log(f"[txlist] {label}: request failed: {e!r}")
        return []


def decode_receipt(w3, tx_hash, expected_to, retries=5):
    """Fetch the REAL receipt for tx_hash, retrying across RPC endpoints on
    429s, and decode any Transfer-shaped mint logs it actually emitted."""
    last_err = None
    for attempt in range(retries):
        for url in RPC_CANDIDATES:
            try:
                w3_try = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 20}))
                receipt = w3_try.eth.get_transaction_receipt(tx_hash)
                to_addr = receipt["to"]
                status = receipt["status"]
                log(f"[receipt] {tx_hash}: to={to_addr} status={status} (expected to={expected_to})")
                if to_addr and to_addr.lower() != expected_to.lower():
                    log(f"[receipt]   WARNING: `to` does NOT match expected address!")
                for entry in receipt["logs"]:
                    topics = entry["topics"]
                    if not topics:
                        continue
                    t0 = topics[0].hex()
                    if len(topics) == 4 and t0 == TRANSFER_TOPIC:
                        token_id = int(topics[3].hex(), 16)
                        owner = "0x" + topics[2].hex()[-40:]
                        frm = "0x" + topics[1].hex()[-40:]
                        log(f"[receipt]   Transfer log: from={frm} to={owner} agentId={token_id}")
                    else:
                        log(f"[receipt]   other log: address={entry['address']} topic0={t0}")
                return receipt
            except Exception as e:
                last_err = e
                if "429" in str(e) or "Too Many Requests" in str(e):
                    time.sleep(2 * (attempt + 1))
                    continue
                log(f"[receipt] {tx_hash} via {url} failed: {e!r}")
        time.sleep(2 * (attempt + 1))
    log(f"[receipt] {tx_hash}: giving up after {retries} rounds, last error: {last_err!r}")
    return None


def main():
    w3, rpc_url = connect()
    latest = w3.eth.block_number
    log(f"[rpc] latest block: {latest}")

    log("\n=== Step 1: bytecode presence ===")
    current_len = check_bytecode(w3, "CURRENT (0x8004A818...)", CURRENT_ADDR)
    candidate_len = check_bytecode(w3, "CANDIDATE (0x8004A169...)", CANDIDATE_ADDR)

    log("\n=== Step 2: EIP-1967 proxy implementation slot ===")
    check_eip1967_impl(w3, "CURRENT", CURRENT_ADDR)
    check_eip1967_impl(w3, "CANDIDATE", CANDIDATE_ADDR)

    log("\n=== Step 3: Basescan source/ABI verification (best-effort) ===")
    check_basescan_source(CURRENT_ADDR, "CURRENT")
    check_basescan_source(CANDIDATE_ADDR, "CANDIDATE")

    log("\n=== Step 4: real agentIds from register() event logs (CURRENT address, mainnet) ===")
    found = find_real_agent_ids(w3, latest)
    if found:
        agent_ids = sorted({f["agentId"] for f in found})[:8]
        log(f"[logs] using REAL agentIds extracted from logs for read test: {agent_ids}")
    else:
        agent_ids = [1, 2, 3]
        log(f"[logs] WARNING: no mint logs found in scanned range -- falling back to ASSUMED sequential ids {agent_ids} (NOT extracted from logs, treat read results below as lower-confidence)")

    log("\n=== Step 5: ownerOf/balanceOf reads against BOTH addresses ===")
    if candidate_len == 0:
        log("[read] CANDIDATE has no bytecode on this chain -- skipping read calls against it (would revert trivially)")
    else:
        try_reads(w3, "CANDIDATE", CANDIDATE_ADDR, agent_ids)
    if current_len == 0:
        log("[read] CURRENT has no bytecode on this chain -- skipping read calls against it")
    else:
        try_reads(w3, "CURRENT", CURRENT_ADDR, agent_ids)

    log("\n=== Step 6: real tx history + real receipts (Basescan-indexed, no assumed range) ===")
    current_txs = fetch_txlist(CURRENT_ADDR, "CURRENT")
    time.sleep(1)
    candidate_txs = fetch_txlist(CANDIDATE_ADDR, "CANDIDATE")

    successful_current = [t for t in current_txs if t.get("isError") == "0"]
    log(f"[txlist] CURRENT: {len(successful_current)} successful tx(s) out of {len(current_txs)} total")
    for tx in successful_current:
        decode_receipt(w3, tx["hash"], CURRENT_ADDR)
        time.sleep(0.5)

    successful_candidate = [t for t in candidate_txs if t.get("isError") == "0"]
    log(f"[txlist] CANDIDATE: {len(successful_candidate)} successful tx(s) out of {len(candidate_txs)} total")
    for tx in successful_candidate:
        decode_receipt(w3, tx["hash"], CANDIDATE_ADDR)
        time.sleep(0.5)

    log("\n=== DONE ===")


if __name__ == "__main__":
    main()
