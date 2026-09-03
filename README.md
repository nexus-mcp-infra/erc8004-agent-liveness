# ERC-8004 Agent Liveness

Checks whether an agent registered in the real ERC-8004 "Trustless Agents" Identity Registry (Base
Sepolia testnet -- see "Chain scope" below for why, despite payment being real USDC on Base mainnet)
is actually alive right now -- not just that it was registered once. NEXUS candidate #10 --
**manual build, not FORGE-generated**, same manual-Cloud-Run-asset pattern as candidates #3/#4/#6/#8/#9/#13/#16.

- `POST /verify-registered-agent {"agent_id": 3}` -- **$0.10/call.**
- MCP tool `verify_registered_agent` at `/mcp`, same params -- **currently free**, see "Known limitations".
- `GET /health`, `GET /.well-known/agent-card.json`, `GET /openapi.json` (has `x-payment-info`),
  `GET /.well-known/402index-verify.txt` (402index claim verification file).

## What this is (and why registration alone isn't enough)

[ERC-8004](https://eips.ethereum.org/EIPS/eip-8004) is a real, live Ethereum standard for on-chain agent
identity: an agent mints an ERC-721 token in an `IdentityRegistry`, whose `tokenURI` points to an off-chain
registration file (JSON: name, description, declared endpoints, `active` flag, supported trust methods). It
went live on Ethereum mainnet 2026-01-29, with reference deployments on Base mainnet and Base/Ethereum/Linea
Sepolia testnets. Registration is a one-time on-chain action -- a real registered agent can go completely
dark (process killed, domain expired, endpoint changed) while its on-chain record persists unchanged forever.
This asset closes that gap: it resolves the real on-chain registration AND performs a real MCP `initialize`
handshake against whatever endpoint the registration declares, right now, at call time -- the same
liveness-vs-registration distinction `agent-verification-api` (candidate #3) already draws for
domain-claimed identities, applied here to on-chain-registered ones.

## Grounding (verified live this session, not assumed from any single source)

- **Contract addresses**, initially from a third-party summary, verified independently via `eth_getCode`
  against `https://sepolia.base.org` before being trusted: `IdentityRegistry`
  (`0x8004A818BFB912233c491871b3d84c89A494BD9e`) and `ReputationRegistry`
  (`0x8004B663056A597Dffe9eCcC1965A193B7388713`) both have real, non-empty deployed bytecode.
- **ABI**, pulled from the reference implementation (`github.com/erc-8004/erc-8004-contracts/abis`), tested
  live against 3 real registered agents (`agentId` 1-3) before being trusted for this asset:
  - Agent 1's `tokenURI` resolves to a `data:application/json;base64,...` URI.
  - Agent 2's resolves to `ipfs://bafkreiff...`.
  - Agent 3's resolves to a real `https://api.snack.money/agent/.../registration.json` URL.
  All 3 of ERC-8004's real URI schemes confirmed working live, not just the one the spec's own examples show.
- **`getSummary` requires a non-empty `clientAddresses` array** -- confirmed live (reverts with
  `"clientAddresses required"` otherwise). This asset calls `getClients(agentId)` first and only calls
  `getSummary` if that returns at least one address; agents with zero feedback correctly report
  `feedback_count: 0` without an RPC error.
- **`agentId=999999` (a real nonexistent token)** correctly reverts with a custom error, confirmed live --
  mapped to `AGENT_NOT_FOUND`, not a crash.

## MCP handshake engine: reused, not reimplemented

Per the task brief's explicit instruction, `_nexus_validate_public_url`, `_nexus_no_redirect_mcp_http_client`,
and `_mcp_handshake_check` are ported **verbatim** from `manual_assets/agent-verification-api/main.py`
(candidate #3) -- same SSRF pre-check, same no-redirect posture (the exact fix applied there after the
2026-08-22 security review found a redirect-based SSRF bypass), same bounded timeout. Not modified beyond the
asset-name constant. This asset's own contribution is upstream of that: resolving an ERC-8004 registration
file (3 URI schemes) and picking a real endpoint out of its `endpoints` array to hand to that engine.

## Chain scope

**Split, deliberately.** x402 payment settles in real USDC on **Base mainnet**. The on-chain
`IdentityRegistry`/`ReputationRegistry` reads -- the actual identity/liveness check -- are on **Base Sepolia
testnet**, not mainnet. This asset still doesn't expose a caller-selectable chain -- no evidence a buyer needs
one for either rail.

## Mainnet cutover (2026-09-03) and same-day partial revert

Originally built and measured on Base Sepolia testnet (x402 payment + registry reads both). Cut over to Base
mainnet same session: x402 settlement moved to the CDP facilitator (`create_facilitator_config()`, same swap
already applied to `ws`/`live-entity-verification`), the payto wallet moved to `NEXUS_X402_PAYTO_ADDRESS`
(fail-fast env var, no placeholder default), and the registry RPC moved to Base mainnet too, at the same two
contract addresses -- that address reuse across chains was confirmed by the operator directly on Basescan
before the cutover, not independently re-verified from the session that made the code change (no outbound
network access to `mainnet.base.org` from that environment).

**Reverted a few hours later, registry-read side only.** Two independent sources (a live `eth_call`, and
Basescan's own "Read as Proxy" tab) confirmed `ownerOf`/`balanceOf` both revert with "execution reverted, no
data" against the IdentityRegistry proxy (`0x8004A818BFB912233c491871b3d84c89A494BD9e`) on Base mainnet --
while `register()` against that same proxy demonstrably works (19 real confirmed mint transactions). The
implementation contract behind the proxy on mainnet (`0xd53dE688e0b0ad436FBdbDa00036832FF6499234`, confirmed
via Basescan's proxy-implementation slot) has **no verified source or ABI anywhere on Etherscan/Basescan** --
so there's no way to confirm the deployed mainnet bytecode still matches
`github.com/erc-8004/erc-8004-contracts` (commit b9e466c) the way the Sepolia deployment's bytecode was
originally confirmed (see "Grounding" above). Continuing to call `ownerOf`/`tokenURI`/`getClients`/`getSummary`
by name against unverified mainnet bytecode risked the exact failure this asset exists to catch, but aimed at
its own buyers instead: a plausible wrong answer (`AGENT_NOT_FOUND` for a real agent) charged for as if
correct.

`BASE_RPC_URL` was reverted to `BASE_SEPOLIA_RPC_URL` (default back to `https://sepolia.base.org`) so the
registry read is on the chain whose bytecode is actually verified working, while `_X402_NETWORK` and the CDP
facilitator stay on Base mainnet -- payment did not revert, only the identity check did. Every buyer-facing
surface (agent-card, OpenAPI descriptions, this README) says this split explicitly rather than implying the
whole asset moved to mainnet.

## Pending: confirm the real mainnet implementation before re-attempting this cutover

Not resolved, left open on purpose rather than guessed at:

- Decompile the bytecode at the mainnet implementation address
  (`0xd53dE688e0b0ad436FBdbDa00036832FF6499234`) directly, since no verified source exists to read instead, OR
- Contact the ERC-8004 team/Foundation to ask for the real source/ABI actually deployed on Base mainnet at
  that implementation address.

Only once one of those confirms the real function names/signatures (which may or may not match
`ownerOf`/`tokenURI`/`getClients`/`getSummary` from the Sepolia-verified reference source) should the registry
read be pointed at Base mainnet again -- and even then, re-verify live against real registered mainnet agents
before trusting it, the same discipline already applied to the original Sepolia grounding.

## Deploy target: Cloud Run

Same pipeline as candidates #4/#3/#6/#8/#9/#13/#16 -- see `skills/infra-deploy-ops`.

```bash
# 1. First deploy -- PUBLIC_DOMAIN not known yet, every real request 421s until step 2.
./scripts/deploy_cloud_run.sh erc8004-agent-liveness manual_assets/erc8004-agent-liveness

# 2. Grab the printed *.run.app URL, then (only if it differs from env-vars.deploy.yaml's guess):
gcloud run services update erc8004-agent-liveness --region us-central1 --project nexus-505016 \
    --update-env-vars PUBLIC_DOMAIN=<the-real-domain>
```

## Known limitations (left unfixed on purpose -- CLAUDE.md SS3, no gate without evidence it's needed)

- **MCP tool calls are not charged.** Same in-process-call pattern as every other manual asset in this
  codebase.
- **`active: false` short-circuits to `REGISTERED_INACTIVE` even if the endpoint is actually live.** Trusts
  the registrant's own self-declaration over an independent liveness check in that one case -- an agent
  lying about being inactive (unusual incentive) would be misreported. Accepted: `active` is the registrant's
  own signal by spec design, overriding it would be second-guessing the standard's own field.
  `REGISTERED_UNREACHABLE` (the opposite failure mode -- declared active, not actually reachable) is this
  asset's actual value-add and is NOT similarly short-circuited.
  - **Endpoint selection is a heuristic, not a spec requirement.** ERC-8004's `endpoints` array is free-form
  (any `name`); this asset prefers `mcp`/`x402`/`a2a`/`web` (in that order) and falls back to the first entry.
  A registration using an unlisted `name` for its only real MCP-capable endpoint would still be picked (name
  matching isn't the only path -- unnamed-preference fallback covers it), but a registration with MULTIPLE
  endpoints where none of the preferred names points to the live one could report `REGISTERED_UNREACHABLE`
  based on the wrong endpoint.
- **IPFS resolution uses a single public gateway (`ipfs.io`).** No fallback gateway -- a registration whose
  CID isn't pinned/reachable via that specific gateway reports `REGISTRATION_FETCH_FAILED` even if the
  content exists on IPFS generally.
- **No per-caller rate limiting.** Fine for a 7-day disposable measurement window.
- **`reputation` is a self-reported, ungated, un-staked signal.** Any EVM address can call
  `ReputationRegistry.giveFeedback` for any `agentId` -- `feedback_count`/`average_value` are real on-chain
  numbers, but nothing stops an agent's own owner from Sybil-feeding themselves. Treat as an unverified
  signal, not a trust score (this caveat is also in the `reputation` field's own description in the API
  schema, not just here).

## Quality gate (2026-08-23, from design not retroactive)

Same 2-agent process as candidates #3/#4/#6/#8/#9/#13/#16 (security lens; functional+quality+buyer-experience
lens), run before the first deploy. Real findings, all fixed before going live:

- **Security (0 exploitable findings):** confirmed the 3 functions ported verbatim from
  `agent-verification-api/main.py` (`_nexus_validate_public_url`, `_nexus_no_redirect_mcp_http_client`,
  `_mcp_handshake_check`) carry the actual SSRF-redirect fix, byte-for-byte, and that the new
  `https://`/IPFS registration-fetch path applies the same defense one layer earlier, before any endpoint is
  extracted -- confirmed NOT to reintroduce that bug class. Two low/informational items, both addressed as
  defense-in-depth even though neither was a confirmed exploit: IPFS CID concatenation (confirmed live it
  couldn't escape the `ipfs.io` host, but now uses `urllib.parse.quote` to confine it to a single path
  segment anyway), and `data:` URI base64 decoding (confirmed linear/non-amplifying, no fix needed).
- **Functional/buyer-experience (1 must-fix, 1 medium, applied):** a registration file whose top-level JSON
  is a non-object (array/string/number -- registrant-controlled content) passed through as `"ok": True` with
  a non-dict `registration`, which every downstream consumer (`_pick_liveness_endpoint`, `_classify_verdict`,
  the response body) assumed was a dict -- an uncaught `AttributeError` became an unhandled 500 **after x402
  payment had already settled**. Fixed: both JSON-parse sites in `_resolve_registration_file` now reject
  non-dict results as `registration_not_an_object` before returning `"ok": True`. Also added the reputation
  gameability caveat (see "Known limitations" above and the `reputation` field's own schema description).
  Two low/nice-to-have items (duplicate-`name` endpoint shadowing, unverified field casing on 2 optional
  registration keys) left as-is -- no evidence yet either matters for real registrations, consistent with
  CLAUDE.md SS3.
- Verified end-to-end against real production data before AND after fixes: 4 real ERC-8004 agent IDs on Base
  Sepolia (1, 2, 3, and a real nonexistent 999999) each produced the correct verdict --
  `REGISTERED_UNREACHABLE` (real registration, endpoint doesn't answer MCP), `REGISTRATION_FETCH_FAILED` x2
  (a real IPFS gateway timeout, and a real dead `https://` registration URL -- both legitimate, not bugs),
  and `AGENT_NOT_FOUND` (real on-chain revert) -- plus real reputation data (74 feedback entries from 12
  distinct clients on agent 1).

## Measurement (candidate #10, 7-day window)

7-day window from 2026-08-23 (real deploy date) -> decision point 2026-08-30. Source of truth:
`traffic_events`/`revenue_events`/`mcp_call_events` (`asset_name = 'erc8004-agent-liveness'`), not Cloud Run
logs. Day 7: if zero real traffic (filtering crawlers), pause/delete the Cloud Run service
(`gcloud run services delete erc8004-agent-liveness --region us-central1 --project nexus-505016`).
