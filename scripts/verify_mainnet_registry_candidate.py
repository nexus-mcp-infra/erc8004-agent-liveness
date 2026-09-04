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
    {
        "name": "totalSupply",
        "inputs": [],
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


def _basescan_api_key():
    import os

    return os.environ.get("BASESCAN_API_KEY", "")


def check_basescan_source(addr, label):
    api_key = _basescan_api_key()
    if not api_key:
        log(f"[basescan] {label}: no BASESCAN_API_KEY secret set in this repo -- skipping source/ABI verification check")
        return None
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
            log(f"[basescan] {label} ({addr}): ContractName={r0.get('ContractName')!r} verified={verified} Proxy={r0.get('Proxy')} Implementation={r0.get('Implementation')!r} CompilerVersion={r0.get('CompilerVersion')!r}")
            return r0
        else:
            log(f"[basescan] {label} ({addr}): unexpected response: {data}")
            return None
    except urllib.error.URLError as e:
        log(f"[basescan] {label} ({addr}): request failed: {e!r}")
        return None


def get_block_with_retry(target, retries=6):
    """eth_getBlockByNumber with retry/rotation across RPC endpoints -- the
    120,000-block guess in the first two runs of this script was never
    actually validated against real timestamps, so before trusting any log
    scan again we confirm what calendar window a given block really is."""
    last_err = None
    for attempt in range(retries):
        for url in RPC_CANDIDATES:
            try:
                w3_try = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 20}))
                return w3_try.eth.get_block(target)
            except Exception as e:
                last_err = e
                if "429" in str(e) or "Too Many Requests" in str(e):
                    time.sleep(1.5 * (attempt + 1))
                    continue
        time.sleep(1.5 * (attempt + 1))
    raise SystemExit(f"[blocktime] could not fetch block {target} after {retries} rounds: {last_err!r}")


def find_block_by_timestamp(target_ts, lo, hi):
    """Binary search for the first block with timestamp >= target_ts."""
    while lo < hi:
        mid = (lo + hi) // 2
        blk = get_block_with_retry(mid)
        if blk["timestamp"] < target_ts:
            lo = mid + 1
        else:
            hi = mid
        time.sleep(0.3)
    return lo


def find_real_agent_ids(w3, from_block, latest_block):
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


def find_real_agent_ids_via_api(addr, label, from_block, latest_block):
    """eth_getLogs via Etherscan v2's proxy module (module=proxy, same module
    that already worked for eth_getTransactionReceipt) instead of the free
    public RPC, which 429'd on every prior run. Uses the block range already
    validated against real timestamps in step 4a -- not re-derived here."""
    api_key = _basescan_api_key()
    if not api_key:
        log(f"[api-logs] {label}: no BASESCAN_API_KEY -- skipping")
        return []
    url = (
        "https://api.etherscan.io/v2/api"
        f"?chainid=8453&module=proxy&action=eth_getLogs"
        f"&fromBlock={hex(from_block)}&toBlock={hex(latest_block)}"
        f"&address={addr}&topic0={TRANSFER_TOPIC}"
        f"&apikey={api_key}"
    )
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            data = json.loads(resp.read())
    except urllib.error.URLError as e:
        log(f"[api-logs] {label}: request failed: {e!r}")
        return []

    result = data.get("result")
    if isinstance(result, str):
        # proxy module surfaces errors as a string result (e.g. range too large)
        log(f"[api-logs] {label}: error/message result: {result!r} (full response: {data})")
        return []
    if not isinstance(result, list):
        log(f"[api-logs] {label}: unexpected response: {data}")
        return []

    log(f"[api-logs] {label} ({addr}): {len(result)} Transfer-topic log(s) found via Etherscan API, block {from_block}-{latest_block}")
    found = []
    for entry in result:
        topics = entry.get("topics", [])
        if len(topics) != 4:
            continue
        token_id = int(topics[3], 16)
        owner = "0x" + topics[2][-40:]
        frm = "0x" + topics[1][-40:]
        tx_hash = entry.get("transactionHash")
        block_num = int(entry.get("blockNumber", "0x0"), 16)
        log(f"[api-logs]   agentId={token_id} from={frm} to={owner} tx={tx_hash} block={block_num}")
        found.append({"agentId": token_id, "owner": owner, "from": frm, "txHash": tx_hash, "blockNumber": block_num})
    return found


def find_real_agent_ids_via_blockscout(addr, label, from_block, latest_block):
    """eth_getLogs equivalent via Blockscout's Base instance -- independent of
    Etherscan/Basescan entirely, no API key, no plan tier. Uses Blockscout's
    Etherscan-compatible legacy API (module=logs&action=getLogs), documented at
    https://docs.blockscout.com/devs/apis/rpc-endpoints/logs -- exact endpoint:
    https://base.blockscout.com/api?module=logs&action=getLogs. Same
    timestamp-validated block range as the other attempts, not re-derived."""
    url = (
        "https://base.blockscout.com/api"
        f"?module=logs&action=getLogs"
        f"&fromBlock={from_block}&toBlock={latest_block}"
        f"&address={addr}&topic0={TRANSFER_TOPIC}"
    )
    log(f"[blockscout] {label}: GET {url}")
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            data = json.loads(resp.read())
    except urllib.error.URLError as e:
        log(f"[blockscout] {label}: request failed: {e!r}")
        return []

    status = data.get("status")
    result = data.get("result")
    if status != "1" or not isinstance(result, list):
        log(f"[blockscout] {label}: status={status!r} message={data.get('message')!r} result={result!r}")
        return []

    log(f"[blockscout] {label} ({addr}): {len(result)} Transfer-topic log(s) found via Blockscout, block {from_block}-{latest_block}")
    found = []
    for entry in result:
        topics = entry.get("topics", [])
        if len(topics) != 4 or not topics[3]:
            continue
        token_id = int(topics[3], 16)
        owner = "0x" + topics[2][-40:]
        frm = "0x" + topics[1][-40:]
        tx_hash = entry.get("transactionHash")
        raw_block = entry.get("blockNumber", "0x0")
        block_num = int(raw_block, 16) if isinstance(raw_block, str) and raw_block.startswith("0x") else int(raw_block or 0)
        log(f"[blockscout]   agentId={token_id} from={frm} to={owner} tx={tx_hash} block={block_num}")
        found.append({"agentId": token_id, "owner": owner, "from": frm, "txHash": tx_hash, "blockNumber": block_num})
    return found


def try_reads(w3, label, addr, agent_ids):
    contract = w3.eth.contract(address=addr, abi=MINIMAL_ABI)
    for tid in agent_ids:
        try:
            owner = contract.functions.ownerOf(tid).call()
            log(f"[read] {label}.ownerOf({tid}) = {owner}")
        except Exception as e:
            log(f"[read] {label}.ownerOf({tid}) REVERTED: {e!r}")
    try:
        supply = contract.functions.totalSupply().call()
        log(f"[read] {label}.totalSupply() = {supply}")
    except Exception as e:
        log(f"[read] {label}.totalSupply() REVERTED/unsupported: {e!r}")


def fetch_txlist(addr, label):
    """Full real transaction history for `addr` on Base mainnet, straight from
    Basescan's indexed API -- no block range guessing, no pre-known hash needed."""
    api_key = _basescan_api_key()
    if not api_key:
        log(f"[txlist] {label}: no BASESCAN_API_KEY secret set -- Basescan's v1 API (no key required) is deprecated as of this run (confirmed: returns status=0, 'deprecated V1 endpoint'), v2 requires a key. Skipping, relying on Step 4's timestamp-verified log scan instead.")
        return []
    url = (
        "https://api.etherscan.io/v2/api"
        f"?chainid=8453&module=account&action=txlist&address={addr}"
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


def fetch_receipt_via_api(tx_hash, retries=3):
    """eth_getTransactionReceipt via the paid Etherscan v2 API (module=proxy)
    instead of the free public RPC -- avoids the 429s that hit every run so
    far. Returns the raw JSON-RPC receipt dict (hex fields) or None."""
    api_key = _basescan_api_key()
    if not api_key:
        return None
    url = (
        "https://api.etherscan.io/v2/api"
        f"?chainid=8453&module=proxy&action=eth_getTransactionReceipt&txhash={tx_hash}&apikey={api_key}"
    )
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(url, timeout=20) as resp:
                data = json.loads(resp.read())
            result = data.get("result")
            if result is None and "error" in data:
                log(f"[api-receipt] {tx_hash}: {data['error']}")
                return None
            return result
        except urllib.error.URLError as e:
            log(f"[api-receipt] {tx_hash}: request failed (attempt {attempt+1}): {e!r}")
            time.sleep(1.5 * (attempt + 1))
    return None


def decode_receipt_json(receipt, expected_to, tx_hash):
    """Decode a raw JSON-RPC receipt (hex fields, as returned by the
    Etherscan proxy API) -- confirms `to` and any Transfer-shaped log."""
    if not receipt:
        log(f"[receipt] {tx_hash}: no receipt returned via API")
        return None
    to_addr = receipt.get("to")
    status = receipt.get("status")
    log(f"[receipt] {tx_hash}: to={to_addr} status={status} (expected to={expected_to})")
    if to_addr and to_addr.lower() != expected_to.lower():
        log(f"[receipt]   WARNING: `to` does NOT match expected address!")
    for entry in receipt.get("logs", []):
        topics = entry.get("topics", [])
        if not topics:
            continue
        t0 = topics[0]
        if len(topics) == 4 and t0.lower() == TRANSFER_TOPIC.lower():
            token_id = int(topics[3], 16)
            owner = "0x" + topics[2][-40:]
            frm = "0x" + topics[1][-40:]
            log(f"[receipt]   Transfer log: from={frm} to={owner} agentId={token_id}")
        else:
            log(f"[receipt]   other log: address={entry.get('address')} topic0={t0}")
    return receipt


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
    current_impl = check_eip1967_impl(w3, "CURRENT", CURRENT_ADDR)
    candidate_impl = check_eip1967_impl(w3, "CANDIDATE", CANDIDATE_ADDR)

    log("\n=== Step 3: Basescan/Etherscan v2 source/ABI verification (proxy + implementation) ===")
    check_basescan_source(CURRENT_ADDR, "CURRENT proxy")
    time.sleep(1.0)
    check_basescan_source(CANDIDATE_ADDR, "CANDIDATE proxy")
    time.sleep(1.0)
    if current_impl:
        check_basescan_source(current_impl, "CURRENT implementation")
        time.sleep(1.0)
    if candidate_impl:
        check_basescan_source(candidate_impl, "CANDIDATE implementation")
        time.sleep(1.0)

    log("\n=== Step 4a: validate the block-time assumption before trusting any range ===")
    import datetime

    latest_block_obj = get_block_with_retry(latest)
    latest_ts = latest_block_obj["timestamp"]
    probe_block = max(0, latest - 120_000)
    probe_block_obj = get_block_with_retry(probe_block)
    probe_ts = probe_block_obj["timestamp"]
    elapsed_s = latest_ts - probe_ts
    log(f"[blocktime] latest block {latest} @ {datetime.datetime.utcfromtimestamp(latest_ts).isoformat()}Z")
    log(f"[blocktime] block {probe_block} (latest-120000) @ {datetime.datetime.utcfromtimestamp(probe_ts).isoformat()}Z")
    log(f"[blocktime] 120,000 blocks = {elapsed_s} real seconds = {elapsed_s / 3600:.1f} hours (assumed 2s/block would be {120_000 * 2 / 3600:.1f} hours)")
    log(f"[blocktime] PREVIOUS TWO RUNS scanned this exact 120,000-block window -- if the hours figure above is much smaller than expected, that scan covered far less real time than intended")

    target_ts = latest_ts - 6 * 24 * 3600  # 6 days back, safe margin over the 2026-09-03 cutover
    verified_from_block = find_block_by_timestamp(target_ts, max(0, latest - 20_000_000), latest)
    verified_from_ts = get_block_with_retry(verified_from_block)["timestamp"]
    log(f"[blocktime] timestamp-verified from_block={verified_from_block} @ {datetime.datetime.utcfromtimestamp(verified_from_ts).isoformat()}Z (target: 6 days before latest)")

    log("\n=== Step 4: real agentIds from register()/Transfer event logs, BOTH addresses, via Etherscan proxy module (not the rate-limited public RPC) ===")
    found_current = find_real_agent_ids_via_api(CURRENT_ADDR, "CURRENT", verified_from_block, latest)
    time.sleep(0.5)
    found_candidate = find_real_agent_ids_via_api(CANDIDATE_ADDR, "CANDIDATE", verified_from_block, latest)

    log("\n=== Step 4b: same query via Blockscout (independent of Etherscan, no key, no known paywall) ===")
    found_current_bs = find_real_agent_ids_via_blockscout(CURRENT_ADDR, "CURRENT", verified_from_block, latest)
    time.sleep(0.5)
    found_candidate_bs = find_real_agent_ids_via_blockscout(CANDIDATE_ADDR, "CANDIDATE", verified_from_block, latest)
    found_current = found_current + found_current_bs
    found_candidate = found_candidate + found_candidate_bs

    found = found_current + found_candidate
    if found:
        agent_ids = sorted({f["agentId"] for f in found})[:8]
        log(f"[logs] using REAL agentIds extracted from logs for read test: {agent_ids}")
        log(f"[logs] SUMMARY: {len(found_current)} real Transfer mint(s) landed on CURRENT, {len(found_candidate)} landed on CANDIDATE")
    else:
        agent_ids = [1, 2, 3]
        log(f"[logs] WARNING: no mint logs found on EITHER address in the timestamp-verified range -- falling back to ASSUMED sequential ids {agent_ids} (NOT extracted from logs, treat read results below as lower-confidence)")

    log("\n=== Step 5: ownerOf/balanceOf reads against BOTH addresses ===")
    if candidate_len == 0:
        log("[read] CANDIDATE has no bytecode on this chain -- skipping read calls against it (would revert trivially)")
    else:
        try_reads(w3, "CANDIDATE", CANDIDATE_ADDR, agent_ids)
    if current_len == 0:
        log("[read] CURRENT has no bytecode on this chain -- skipping read calls against it")
    else:
        try_reads(w3, "CURRENT", CURRENT_ADDR, agent_ids)

    log("\n=== Step 6: real receipts for any tx hashes found via step 4's log scan ===")
    log("[txlist] account-module txlist confirmed paywalled on this Etherscan plan for Base (run 4: "
        "'Free API access is not supported for this chain') -- not retrying it per instruction. "
        "Using the real tx hashes decoded from step 4's Transfer logs instead.")
    for f in found_current:
        r = fetch_receipt_via_api(f["txHash"])
        decode_receipt_json(r, CURRENT_ADDR, f["txHash"])
        time.sleep(0.3)
    for f in found_candidate:
        r = fetch_receipt_via_api(f["txHash"])
        decode_receipt_json(r, CANDIDATE_ADDR, f["txHash"])
        time.sleep(0.3)
    if not found_current and not found_candidate:
        log("[txlist] no Transfer logs found on either address in step 4 -- nothing to fetch receipts for")

    log("\n=== DONE ===")


if __name__ == "__main__":
    main()
