"""
erc8004-agent-liveness -- NEXUS candidate #10 (manual build, no FORGE).

Checks whether an agent REGISTERED in the real, live ERC-8004 "Trustless
Agents" Identity Registry (https://eips.ethereum.org/EIPS/eip-8004, live on
Base Sepolia testnet + Base/Ethereum mainnet since 2026-01-29) is actually
alive right now -- not just that it was registered once. Registration alone
proves nothing about current liveness: an agent can mint an ERC-721
identity token, publish a registration file, and then go dark forever while
the on-chain record persists unchanged. This asset closes that gap the same
way agent-verification-api (candidate #3) closes it for domain-claimed
identities: real, verified on-chain lookups fused with a real, live MCP
`initialize` handshake against whatever endpoint the agent's own
registration file declares -- not a cached/simulated check.

**Grounding, verified live this session (not assumed from any single
source; a third-party summary of contract addresses was cross-checked
against real on-chain bytecode before being trusted at all)**:
- IdentityRegistry (`0x8004A818BFB912233c491871b3d84c89A494BD9e`) and
  ReputationRegistry (`0x8004B663056A597Dffe9eCcC1965A193B7388713`) on Base
  Sepolia both have real deployed bytecode (`eth_getCode`, non-empty,
  confirmed via the public `https://sepolia.base.org` RPC).
- Real ABI pulled from the reference implementation
  (github.com/erc-8004/erc-8004-contracts/abis) -- the minimal subset used
  here (`ownerOf`, `tokenURI`, `getClients`, `getSummary`) was called live
  against 3 real registered agents (IDs 1-3) before being trusted: agent 1's
  `tokenURI` resolves to a `data:` URI, agent 2's to an `ipfs://` CID, agent
  3's to a real `https://` URL -- all 3 real ERC-8004-spec URI schemes
  confirmed working, not just the one the spec examples happen to show.
  `getSummary` requires a non-empty `clientAddresses` array (reverts
  otherwise, confirmed live) -- this asset calls `getClients` first and only
  calls `getSummary` if that returns at least one address.
- Reused verbatim from `agent-verification-api/main.py` (candidate #3,
  already SSRF-hardened and reviewed): `_nexus_validate_public_url`, the
  no-redirect MCP httpx client factory, and `_mcp_handshake_check` --
  same real `initialize` handshake against a caller/registration-declared
  endpoint, same defenses (SSRF pre-check, no redirects followed, bounded
  timeout). Not reimplemented, not modified beyond renaming the asset-name
  constant, per the task brief's explicit instruction to reuse this engine.

**Chain scope, on purpose**: Base Sepolia testnet only, same network every
other x402 payment in this codebase already uses -- not because ERC-8004
isn't live on Base/Ethereum mainnet too (it is, verified live), but because
adding caller-selectable mainnet RPC calls widens scope without evidence a
buyer needs it for a 7-day probation candidate (CLAUDE.md SS3: no feature
without evidence it's needed).
"""

import asyncio
import base64
import ipaddress
import json
import os
import socket
import sys
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Annotated, Literal, Optional
from urllib.parse import urljoin, urlparse

import httpx
from dotenv import load_dotenv
from web3 import Web3
from web3.exceptions import ContractCustomError, ContractLogicError, Web3Exception

load_dotenv()

from fastapi import FastAPI, HTTPException
from fastapi.openapi.utils import get_openapi as _fastapi_get_openapi
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import BaseModel, Field

from x402.http import FacilitatorConfig, HTTPFacilitatorClient, PaymentOption
from x402.http.middleware.fastapi import PaymentMiddlewareASGI
from x402.http.types import RouteConfig
from x402.mechanisms.evm.exact import ExactEvmServerScheme
from x402.schemas import Network
from x402.server import x402ResourceServer

_NEXUS_ASSET_NAME = "erc8004-agent-liveness"

# ---------------------------------------------------------------
# ERC-8004 registry config -- Base Sepolia testnet. Addresses + ABI subset
# verified live against real deployed bytecode and real registered agents
# this session, see module docstring.
# ---------------------------------------------------------------
_BASE_SEPOLIA_RPC = os.getenv("BASE_SEPOLIA_RPC_URL", "https://sepolia.base.org")
_IDENTITY_REGISTRY_ADDRESS = "0x8004A818BFB912233c491871b3d84c89A494BD9e"
_REPUTATION_REGISTRY_ADDRESS = "0x8004B663056A597Dffe9eCcC1965A193B7388713"

_IDENTITY_ABI = [
    {"inputs": [{"internalType": "uint256", "name": "tokenId", "type": "uint256"}],
     "name": "ownerOf", "outputs": [{"internalType": "address", "name": "", "type": "address"}],
     "stateMutability": "view", "type": "function"},
    {"inputs": [{"internalType": "uint256", "name": "tokenId", "type": "uint256"}],
     "name": "tokenURI", "outputs": [{"internalType": "string", "name": "", "type": "string"}],
     "stateMutability": "view", "type": "function"},
]
_REPUTATION_ABI = [
    {"inputs": [{"internalType": "uint256", "name": "agentId", "type": "uint256"}],
     "name": "getClients", "outputs": [{"internalType": "address[]", "name": "", "type": "address[]"}],
     "stateMutability": "view", "type": "function"},
    {"inputs": [
        {"internalType": "uint256", "name": "agentId", "type": "uint256"},
        {"internalType": "address[]", "name": "clientAddresses", "type": "address[]"},
        {"internalType": "string", "name": "tag1", "type": "string"},
        {"internalType": "string", "name": "tag2", "type": "string"}],
     "name": "getSummary", "outputs": [
        {"internalType": "uint64", "name": "count", "type": "uint64"},
        {"internalType": "int128", "name": "summaryValue", "type": "int128"},
        {"internalType": "uint8", "name": "summaryValueDecimals", "type": "uint8"}],
     "stateMutability": "view", "type": "function"},
]

_w3 = Web3(Web3.HTTPProvider(_BASE_SEPOLIA_RPC, request_kwargs={"timeout": 10}))
_identity_contract = _w3.eth.contract(
    address=Web3.to_checksum_address(_IDENTITY_REGISTRY_ADDRESS), abi=_IDENTITY_ABI)
_reputation_contract = _w3.eth.contract(
    address=Web3.to_checksum_address(_REPUTATION_REGISTRY_ADDRESS), abi=_REPUTATION_ABI)


def _fetch_agent_registration_onchain(agent_id: int) -> dict:
    """Synchronous (web3.py has no native async HTTP provider used here) --
    always called via asyncio.to_thread from async code, never inline."""
    try:
        owner = _identity_contract.functions.ownerOf(agent_id).call()
    except (ContractCustomError, ContractLogicError):
        return {"found": False}
    except Web3Exception as exc:
        return {"found": False, "rpc_error": type(exc).__name__}

    try:
        token_uri = _identity_contract.functions.tokenURI(agent_id).call()
    except (ContractCustomError, ContractLogicError, Web3Exception):
        return {"found": True, "owner": owner, "token_uri": None}

    return {"found": True, "owner": owner, "token_uri": token_uri}


def _fetch_reputation_summary_onchain(agent_id: int) -> dict:
    try:
        clients = _reputation_contract.functions.getClients(agent_id).call()
    except (ContractCustomError, ContractLogicError, Web3Exception):
        return {"available": False}
    if not clients:
        return {"available": True, "feedback_count": 0, "distinct_clients": 0,
                "average_value": None, "value_decimals": None}
    try:
        count, summary_value, decimals = _reputation_contract.functions.getSummary(
            agent_id, clients, "", "").call()
    except (ContractCustomError, ContractLogicError, Web3Exception):
        return {"available": True, "feedback_count": None, "distinct_clients": len(clients),
                "average_value": None, "value_decimals": None}
    avg = (summary_value / (10 ** decimals)) if count else None
    return {
        "available": True, "feedback_count": count, "distinct_clients": len(clients),
        "average_value": avg, "value_decimals": decimals,
    }


# ---------------------------------------------------------------
# Registration-file resolution -- ERC-8004 tokenURI is one of 3 real
# schemes (confirmed live against 3 real registered agents this session):
# data:application/json;base64,..., ipfs://<cid>, or a plain https:// URL.
# The https:// case is caller/registrant-controlled content -- same SSRF
# posture as agent-verification-api's agent-card fetch applies.
# ---------------------------------------------------------------
_IPFS_GATEWAY = "https://ipfs.io/ipfs/"
_MAX_REGISTRATION_BYTES = 262_144  # 256KB -- a registration file is a small JSON document


def _nexus_validate_public_url(url: str) -> None:
    """Ported verbatim from agent-verification-api/main.py."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(400, "endpoint URL must be http(s)")
    if not parsed.hostname:
        raise HTTPException(400, "endpoint URL has no hostname")
    try:
        addrs = socket.getaddrinfo(parsed.hostname, None)
    except socket.gaierror:
        raise HTTPException(400, f"Could not resolve host: {parsed.hostname}")
    for family, _, _, _, sockaddr in addrs:
        ip = ipaddress.ip_address(sockaddr[0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
            raise HTTPException(400, "endpoint URL resolves to a non-public address")


async def _resolve_registration_file(token_uri: str) -> dict:
    """Returns {"ok": True, "registration": {...}} or {"ok": False, "error_code": ...}.
    Never raises -- a malformed/unreachable registration must not crash the request,
    same discipline as every upstream fetcher in this codebase."""
    if token_uri.startswith("data:"):
        try:
            header, _, payload = token_uri.partition(",")
            if ";base64" not in header:
                return {"ok": False, "error_code": "data_uri_not_base64"}
            raw = base64.b64decode(payload)
            if len(raw) > _MAX_REGISTRATION_BYTES:
                return {"ok": False, "error_code": "registration_too_large"}
            parsed = json.loads(raw)
            if not isinstance(parsed, dict):
                return {"ok": False, "error_code": "registration_not_an_object"}
            return {"ok": True, "registration": parsed}
        except Exception as exc:
            return {"ok": False, "error_code": f"data_uri_error:{type(exc).__name__}"}

    if token_uri.startswith("ipfs://"):
        # urllib.parse.quote (not raw concatenation) confines a malicious on-chain CID
        # to a single ipfs.io PATH segment -- security review, 2026-08-23: a CID
        # containing e.g. "../" can't escape the ipfs.io HOST this way (already
        # confirmed live that plain concatenation couldn't either -- httpx doesn't
        # reinterpret path-relative segments against the host -- this is defense in
        # depth, not a fix for a confirmed exploit).
        from urllib.parse import quote as _urlquote
        cid = token_uri[len("ipfs://"):]
        fetch_url = _IPFS_GATEWAY + _urlquote(cid, safe="")
    elif token_uri.startswith(("http://", "https://")):
        try:
            _nexus_validate_public_url(token_uri)
        except HTTPException as exc:
            return {"ok": False, "error_code": f"ssrf_blocked:{exc.detail}"}
        fetch_url = token_uri
    else:
        return {"ok": False, "error_code": f"unsupported_uri_scheme:{token_uri.split(':', 1)[0]}"}

    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            resp = await client.get(fetch_url, headers={"User-Agent": "erc8004-agent-liveness/1.0"})
    except httpx.TimeoutException:
        return {"ok": False, "error_code": "registration_fetch_timeout"}
    except httpx.HTTPError as exc:
        return {"ok": False, "error_code": f"registration_fetch_error:{type(exc).__name__}"}

    if resp.status_code != 200:
        return {"ok": False, "error_code": f"registration_fetch_http_{resp.status_code}"}
    if len(resp.content) > _MAX_REGISTRATION_BYTES:
        return {"ok": False, "error_code": "registration_too_large"}
    try:
        parsed = resp.json()
    except Exception:
        return {"ok": False, "error_code": "registration_invalid_json"}
    # Functional review, 2026-08-23: a registration file whose top-level JSON is an
    # array/string/number (registrant-controlled content, not caller input) passed
    # through as "ok": True with a non-dict `registration` -- every downstream .get()
    # call (_pick_liveness_endpoint, _classify_verdict, the response body) assumed a
    # dict and crashed with an uncaught AttributeError -> unhandled 500, AFTER x402
    # payment had already settled. One check here fixes all three call sites, since
    # `registration` becomes None (not a bad dict) wherever this returns not-ok.
    if not isinstance(parsed, dict):
        return {"ok": False, "error_code": "registration_not_an_object"}
    return {"ok": True, "registration": parsed}


_PREFERRED_ENDPOINT_NAMES = ("mcp", "x402", "a2a", "web")


def _pick_liveness_endpoint(registration: dict) -> Optional[str]:
    """ERC-8004's registration schema has a free-form `endpoints` array
    (name/endpoint pairs, protocol-specific) -- no single required
    transport. Prefers an endpoint explicitly named for a protocol this
    asset can meaningfully liveness-check, falls back to the first endpoint
    present. Returns None if the registration has no endpoints at all."""
    endpoints = registration.get("endpoints")
    if not isinstance(endpoints, list) or not endpoints:
        return None
    by_name = {}
    for ep in endpoints:
        if isinstance(ep, dict) and isinstance(ep.get("name"), str) and isinstance(ep.get("endpoint"), str):
            by_name.setdefault(ep["name"].strip().lower(), ep["endpoint"])
    for preferred in _PREFERRED_ENDPOINT_NAMES:
        if preferred in by_name:
            return by_name[preferred]
    return next(iter(by_name.values()), None)


def _nexus_no_redirect_mcp_http_client(headers=None, timeout=None, auth=None) -> httpx.AsyncClient:
    """Ported verbatim from agent-verification-api/main.py -- see that
    file's docstring for why follow_redirects must be False here."""
    kwargs: dict = {"follow_redirects": False, "timeout": timeout or httpx.Timeout(10.0)}
    if headers is not None:
        kwargs["headers"] = headers
    if auth is not None:
        kwargs["auth"] = auth
    return httpx.AsyncClient(**kwargs)


async def _mcp_handshake_check(agent_endpoint_url: str) -> dict:
    """Ported verbatim from agent-verification-api/main.py (candidate #3) --
    same real MCP `initialize` handshake, same SSRF guard, same no-redirect
    posture. Reused per the task brief's explicit instruction, not
    reimplemented."""
    mcp_url = urljoin(agent_endpoint_url.rstrip('/') + '/', 'mcp/')
    _nexus_validate_public_url(mcp_url)
    try:
        async with asyncio.timeout(10.0):
            async with streamablehttp_client(
                mcp_url, httpx_client_factory=_nexus_no_redirect_mcp_http_client
            ) as (read, write, _):
                async with ClientSession(read, write) as session:
                    init_result = await session.initialize()
                    server_info = getattr(init_result, 'serverInfo', None)
                    tools_result = await session.list_tools()
        return {
            'reachable': True,
            'server_name': getattr(server_info, 'name', None) if server_info else None,
            'server_version': getattr(server_info, 'version', None) if server_info else None,
            'tool_count': len(tools_result.tools) if tools_result else 0,
        }
    except (asyncio.TimeoutError, TimeoutError):
        return {'reachable': False, 'error_code': 'mcp_timeout'}
    except Exception as exc:
        return {'reachable': False, 'error_code': f'mcp_error:{type(exc).__name__}'}


_Verdict = Literal[
    "AGENT_NOT_FOUND", "REGISTRATION_FETCH_FAILED", "REGISTERED_INACTIVE",
    "REGISTERED_NO_ENDPOINT_DECLARED", "REGISTERED_LIVE", "REGISTERED_UNREACHABLE",
]


def _classify_verdict(registration_ok: bool, registration: Optional[dict],
                       endpoint: Optional[str], handshake: Optional[dict]) -> str:
    if not registration_ok:
        return "REGISTRATION_FETCH_FAILED"
    # Spec doesn't mandate `active`; absence is treated as "not declared inactive",
    # not as a positive liveness signal -- the MCP handshake is the actual liveness
    # proof, `active` is only ever used to short-circuit to INACTIVE.
    if registration.get("active") is False:
        return "REGISTERED_INACTIVE"
    if endpoint is None:
        return "REGISTERED_NO_ENDPOINT_DECLARED"
    if handshake and handshake.get("reachable"):
        return "REGISTERED_LIVE"
    return "REGISTERED_UNREACHABLE"


async def _verify_registered_agent_core(agent_id: int) -> dict:
    onchain = await asyncio.to_thread(_fetch_agent_registration_onchain, agent_id)
    if not onchain.get("found"):
        return {
            "agent_id": agent_id,
            "verdict": "AGENT_NOT_FOUND",
            "owner": None,
            "registration": None,
            "endpoint_checked": None,
            "mcp_handshake": None,
            "reputation": None,
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        }

    owner = onchain.get("owner")
    token_uri = onchain.get("token_uri")
    reg_result = await _resolve_registration_file(token_uri) if token_uri else {
        "ok": False, "error_code": "no_token_uri"}

    registration = reg_result.get("registration") if reg_result.get("ok") else None
    endpoint = _pick_liveness_endpoint(registration) if registration else None
    handshake = None
    if endpoint:
        try:
            handshake = await _mcp_handshake_check(endpoint)
        except HTTPException as exc:
            # _mcp_handshake_check (reused verbatim from agent-verification-api) raises
            # HTTPException when its internal SSRF pre-check rejects the endpoint --
            # correct there because that endpoint is caller-supplied input (400 = "you
            # gave me a bad URL"). Here the endpoint comes from the AGENT'S OWN
            # registration, which the buyer never chose and can't fix -- 400ing the
            # whole call would charge a buyer for an error they didn't cause. Found via
            # this asset's own smoke testing, 2026-08-23 (agent 3's real registration
            # declares a non-resolvable/private-looking endpoint). Treated as a normal
            # unreachable result instead, same shape _mcp_handshake_check itself returns
            # for a timeout or connection failure.
            handshake = {"reachable": False, "error_code": f"endpoint_rejected:{exc.detail}"}

    verdict = _classify_verdict(reg_result.get("ok", False), registration, endpoint, handshake)
    reputation = await asyncio.to_thread(_fetch_reputation_summary_onchain, agent_id)

    return {
        "agent_id": agent_id,
        "verdict": verdict,
        "owner": owner,
        "registration": {
            "ok": reg_result.get("ok", False),
            "error_code": reg_result.get("error_code"),
            "name": registration.get("name") if registration else None,
            "description": registration.get("description") if registration else None,
            "active": registration.get("active") if registration else None,
            "x402_support": registration.get("x402Support") if registration else None,
            "supported_trust": registration.get("supportedTrust") if registration else None,
        },
        "endpoint_checked": endpoint,
        "mcp_handshake": handshake,
        "reputation": reputation,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------
# Supabase telemetry -- anon key only, never service_role. Fully stateless
# otherwise (unlike candidate #16) -- no NEXUS-owned table beyond the
# standard telemetry trio.
# ---------------------------------------------------------------
_NEXUS_SUPABASE_URL = os.getenv("SUPABASE_URL")
_NEXUS_SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY")

_nexus_bg_tasks: set = set()


def _nexus_fire_and_forget(coro):
    task = asyncio.create_task(coro)
    _nexus_bg_tasks.add(task)
    task.add_done_callback(_nexus_bg_tasks.discard)
    return task


def _nexus_truncate_ip(raw_ip: Optional[str]) -> Optional[str]:
    if not raw_ip:
        return None
    if ":" in raw_ip and "." not in raw_ip:
        segments = [s for s in raw_ip.split(":") if s]
        head = segments[:4] if len(segments) >= 4 else segments
        return (":".join(head) + "::/64") if head else None
    octets = raw_ip.split(".")
    if len(octets) == 4 and all(o.isdigit() for o in octets):
        return f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
    return None


async def _nexus_supabase_insert(table: str, payload: dict) -> None:
    if not _NEXUS_SUPABASE_URL or not _NEXUS_SUPABASE_ANON_KEY:
        return
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            await client.post(
                f"{_NEXUS_SUPABASE_URL}/rest/v1/{table}",
                json=payload,
                headers={
                    "apikey": _NEXUS_SUPABASE_ANON_KEY,
                    "Authorization": f"Bearer {_NEXUS_SUPABASE_ANON_KEY}",
                    "Content-Type": "application/json",
                    "Prefer": "return=minimal",
                },
            )
    except Exception as e:
        print(f"[WARN] Supabase insert to {table!r} failed: {e}", file=sys.stderr)


async def _nexus_log_mcp_call_event(tool_id: str, success: bool, latency_ms: int) -> None:
    await _nexus_supabase_insert("mcp_call_events", {
        "tool_id": tool_id,
        "asset_name": _NEXUS_ASSET_NAME,
        "success": success,
        "latency_ms": latency_ms,
        "agent_framework": "mcp",
        "price_charged": 0,  # MCP path is free today -- see README "Known limitations"
    })


# ---------------------------------------------------------------
# MCP server (Streamable HTTP)
# ---------------------------------------------------------------
_public_domain = os.getenv("PUBLIC_DOMAIN", "*")
if _public_domain == "*":
    print(
        "[WARN] PUBLIC_DOMAIN is unset -- every real request will get 421'd once "
        "deployed publicly (fails closed). Set it to the real Cloud Run domain and "
        "redeploy.", file=sys.stderr,
    )

mcp = FastMCP(
    "erc8004-agent-liveness",
    stateless_http=True,
    host="0.0.0.0",
    streamable_http_path="/",
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=["localhost:*", "127.0.0.1:*", _public_domain, _public_domain + ":*"],
        allowed_origins=["http://localhost:*", "http://127.0.0.1:*", "https://" + _public_domain],
    ),
)

_MAX_AGENT_ID = 2 ** 256 - 1


def _validate_agent_id(agent_id: int) -> int:
    if not isinstance(agent_id, int) or isinstance(agent_id, bool) or agent_id < 0 or agent_id > _MAX_AGENT_ID:
        raise ValueError("agent_id must be a non-negative integer")
    return agent_id


@mcp.tool()
async def verify_registered_agent(agent_id: int, ctx: Context = None) -> dict:
    """Checks whether an agent registered in the real ERC-8004 Identity
    Registry (Base Sepolia testnet) is actually alive right now: resolves
    its on-chain registration file, then performs a real MCP `initialize`
    handshake against whatever endpoint it declares. verdict is one of
    AGENT_NOT_FOUND, REGISTRATION_FETCH_FAILED, REGISTERED_INACTIVE,
    REGISTERED_NO_ENDPOINT_DECLARED, REGISTERED_LIVE, REGISTERED_UNREACHABLE.
    """
    start = time.monotonic()
    success = False
    try:
        agent_id = _validate_agent_id(agent_id)
        result = await _verify_registered_agent_core(agent_id)
        success = True
        return result
    finally:
        latency_ms = int((time.monotonic() - start) * 1000)
        _nexus_fire_and_forget(_nexus_log_mcp_call_event("verify_registered_agent", success, latency_ms))


# ---------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    async with mcp.session_manager.run():
        yield


app = FastAPI(
    title="ERC-8004 Agent Liveness",
    description=(
        "Checks whether an agent registered in the real ERC-8004 Identity Registry (Base Sepolia "
        "testnet) is actually alive right now -- resolves its on-chain registration file and performs "
        "a real MCP handshake against its declared endpoint, not just a cached registration check."
    ),
    version="1.0.0",
    contact={"email": "dasaanrod@gmail.com"},
    lifespan=lifespan,
)


# ---------------------------------------------------------------
# MCP listen-connection timeout -- fixes the erc8004-agent-liveness cost
# spike confirmed 2026-09-03 (see patch_mcp_listen_timeout.py for the full
# root-cause writeup). Third-party MCP-monitoring bots open GET /mcp/
# "listen" connections (per the Streamable HTTP transport spec) and this
# asset -- which never pushes server-initiated notifications -- never
# closes them, so every one rode Cloud Run's full 300s request timeout and
# was billed for the whole duration. This applies ONLY to GET requests
# under /mcp -- the paid POST tool-call path and every other route are
# completely untouched.
# ---------------------------------------------------------------
_NEXUS_MCP_LISTEN_TIMEOUT_SECONDS = 25


class _NexusMcpListenTimeoutMiddleware:
    """Pure ASGI middleware. Enforces a short idle timeout on GET /mcp
    listen connections only. On timeout, cancels the inner call and lets
    the ASGI server close the underlying connection -- equivalent to a
    normal disconnect from the client's point of view, which any
    SSE-based MCP client already has to handle and reconnect from."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if (
            scope["type"] == "http"
            and scope.get("method") == "GET"
            and scope.get("path", "").rstrip("/").startswith("/mcp")
        ):
            try:
                await asyncio.wait_for(
                    self.app(scope, receive, send),
                    timeout=_NEXUS_MCP_LISTEN_TIMEOUT_SECONDS,
                )
            except asyncio.TimeoutError:
                # Connection closes here -- no further ASGI messages are
                # sent, which is the correct way to end a still-open SSE
                # response early. Intentionally swallowed: this is an
                # expected, routine cutoff, not an error condition.
                return
        else:
            await self.app(scope, receive, send)


app.add_middleware(_NexusMcpListenTimeoutMiddleware)


# --- x402: pay-per-call in USDC, Base Sepolia testnet -- same wallet,
#     facilitator and self-payment-bug fix as the sibling manual assets
#     (skills/x402-payments). $0.10: between the $0.01-0.02 data-packaging
#     tier and agent-verification-api's $0.35 multi-signal-ensemble tier --
#     this does 2 real on-chain reads, 1 real registration-file fetch
#     (data:/ipfs:/https:), and 1 real MCP handshake, but no paid WHOIS
#     spend and no 4-signal Bayesian fusion. ---
_X402_EVM_ADDRESS = os.getenv("X402_WALLET_ADDRESS", "0xYOUR_WALLET_ADDRESS_HERE")
_X402_NETWORK: Network = "eip155:84532"  # Base Sepolia testnet
_X402_PRICE = os.getenv("X402_PRICE", "$0.10")

if not _X402_PRICE or not _X402_PRICE.startswith("$"):
    print(
        f"[WARN] X402_PRICE ({_X402_PRICE!r}) doesn't look like a price string "
        "(expected something like '$0.10'). Falling back to '$0.10' so the "
        "server can still boot -- fix X402_PRICE before deploying.",
        file=sys.stderr,
    )
    _X402_PRICE = "$0.10"

_looks_like_evm_address = (
    _X402_EVM_ADDRESS.startswith("0x")
    and len(_X402_EVM_ADDRESS) == 42
    and all(c in "0123456789abcdefABCDEF" for c in _X402_EVM_ADDRESS[2:])
)
if not _looks_like_evm_address:
    print(
        f"[WARN] X402_WALLET_ADDRESS ({_X402_EVM_ADDRESS!r}) doesn't look like a "
        "real EVM address (expected '0x' + 40 hex chars). The server will still "
        "boot and issue 402 challenges, but payments will have nowhere real to "
        "settle. See README.md.",
        file=sys.stderr,
    )

_x402_facilitator = HTTPFacilitatorClient(FacilitatorConfig(url="https://x402.org/facilitator"))
_x402_server = x402ResourceServer(_x402_facilitator)
_x402_server.register(_X402_NETWORK, ExactEvmServerScheme())


async def _nexus_log_x402_revenue_event(ctx) -> None:
    try:
        result = getattr(ctx, "result", None)
        requirements = getattr(ctx, "requirements", None)
        if result is None or requirements is None or not getattr(result, "success", False):
            return
        raw_amount = getattr(requirements, "amount", None)
        amount_eur = int(raw_amount) / 1_000_000 if raw_amount is not None else None
        await _nexus_supabase_insert("revenue_events", {
            "asset_name": _NEXUS_ASSET_NAME,
            "amount_eur": amount_eur,
            "pricing_model": "x402",
            "stripe_event_id": None,
            "customer_id": getattr(result, "payer", None),
        })
    except Exception:
        pass


_x402_server.on_after_settle(_nexus_log_x402_revenue_event)

_X402_ROUTES: dict[str, RouteConfig] = {
    "POST /verify-registered-agent": RouteConfig(
        accepts=[PaymentOption(scheme="exact", pay_to=_X402_EVM_ADDRESS, price=_X402_PRICE, network=_X402_NETWORK)],
        mime_type="application/json",
        description="Check whether an ERC-8004-registered agent is actually alive right now",
    ),
}
app.add_middleware(PaymentMiddlewareASGI, routes=_X402_ROUTES, server=_x402_server)

# --- PATCH traffic_log_middleware_order_v1 ---
@app.middleware("http")
async def _nexus_traffic_log(request, call_next):
    response = await call_next(request)
    ip = request.client.host if request.client else None
    _nexus_fire_and_forget(_nexus_supabase_insert("traffic_events", {
        "asset_name": _NEXUS_ASSET_NAME,
        "ip_range": _nexus_truncate_ip(ip),
        "method": request.method,
        "path": request.url.path,
        "status": response.status_code,
    }))
    return response



class VerifyRegisteredAgentRequest(BaseModel):
    agent_id: Annotated[int, Field(..., ge=0, le=_MAX_AGENT_ID,
        description="ERC-8004 IdentityRegistry token ID (agentId) on Base Sepolia testnet.")]


class RegistrationInfo(BaseModel):
    ok: bool
    error_code: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None
    active: Optional[bool] = None
    x402_support: Optional[bool] = None
    supported_trust: Optional[list] = None


class ReputationInfo(BaseModel):
    available: bool
    feedback_count: Optional[int] = None
    distinct_clients: Optional[int] = None
    average_value: Optional[float] = None
    value_decimals: Optional[int] = None


class VerifyRegisteredAgentResponse(BaseModel):
    agent_id: int
    verdict: _Verdict
    owner: Optional[str] = Field(None, description="EVM address currently owning this agent's ERC-721 identity token.")
    registration: Optional[RegistrationInfo] = None
    endpoint_checked: Optional[str] = Field(None, description="Endpoint URL the MCP handshake was attempted against, from the registration's own endpoints array.")
    mcp_handshake: Optional[dict] = Field(None, description="reachable/server_name/server_version/tool_count, or reachable=false with error_code.")
    reputation: Optional[ReputationInfo] = Field(None, description="Aggregate feedback from the ReputationRegistry, informational only -- never gates verdict. "
        "Self-reported: any EVM address can call giveFeedback for any agentId, unverified and un-staked -- "
        "treat this as an unverified signal, not a trust score.")
    evaluated_at: str


@app.post(
    "/verify-registered-agent",
    response_model=VerifyRegisteredAgentResponse,
    responses={
        422: {"description": "invalid request body (agent_id out of range)"},
    },
)
async def verify_registered_agent_endpoint(payload: VerifyRegisteredAgentRequest) -> dict:
    """Checks whether an ERC-8004-registered agent (Base Sepolia testnet) is
    actually alive right now.

    `verdict` meanings:
    - AGENT_NOT_FOUND: no agent is registered with this agent_id (ownerOf reverted).
    - REGISTRATION_FETCH_FAILED: the agent exists but its registration file
      (data:/ipfs:/https:) could not be resolved or parsed.
    - REGISTERED_INACTIVE: the registration file itself declares `active: false`.
    - REGISTERED_NO_ENDPOINT_DECLARED: registration resolved but declares no
      checkable endpoint.
    - REGISTERED_LIVE: a real MCP `initialize` handshake against the
      declared endpoint succeeded right now.
    - REGISTERED_UNREACHABLE: registered, active, has a declared endpoint --
      but the live handshake failed. This is the actual gap this asset
      exists to catch: a real on-chain registration that no longer
      corresponds to anything running.

    Payment (x402, $0.10) settles BEFORE this handler runs, at the ASGI
    middleware layer ahead of request validation -- a call is charged even
    if it resolves to AGENT_NOT_FOUND or 422s: the verdict itself (including
    a negative one) is the paid product, same convention as every other
    paid asset in this codebase."""
    return await _verify_registered_agent_core(payload.agent_id)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


_FAVICON_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
)


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    from fastapi.responses import Response
    return Response(content=_FAVICON_PNG, media_type="image/png")


# --- 402index.io domain claim verification (POST /api/v1/claim -- filled in
#     after the real Cloud Run domain is known, see README "Deploy") ---
_NEXUS_402INDEX_VERIFY_HASH = os.getenv("NEXUS_402INDEX_VERIFY_TOKEN", "")


@app.get("/.well-known/402index-verify.txt", include_in_schema=False)
async def _nexus_402index_verify():
    from fastapi.responses import PlainTextResponse
    if not _NEXUS_402INDEX_VERIFY_HASH:
        raise HTTPException(404, "no 402index claim on file")
    return PlainTextResponse(content=_NEXUS_402INDEX_VERIFY_HASH)


@app.get("/.well-known/agent-card.json", include_in_schema=False)
async def agent_card() -> dict:
    base = f"https://{_public_domain}" if _public_domain != "*" else "https://erc8004-agent-liveness.example"
    return {
        "name": "ERC-8004 Agent Liveness",
        "description": "Checks whether an ERC-8004-registered agent is actually alive right now, "
                        "not just registered once.",
        "url": base,
        "version": "1.0.0",
        "documentationUrl": f"{base}/docs",
        "provider": {"organization": "nexus-mcp-infra", "url": "https://github.com/nexus-mcp-infra"},
        "capabilities": {"streaming": False, "pushNotifications": False, "stateTransitionHistory": False},
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "additionalInterfaces": [{"url": f"{base}/mcp", "transport": "MCP"}],
        "skills": [
            {
                "id": "nexus_erc8004_agent_liveness_verify_registered_agent",
                "name": "Verify Registered Agent Liveness",
                "description": "Check whether an ERC-8004-registered agent is actually alive right "
                                "now via a real MCP handshake against its declared endpoint.",
                "tags": ["erc-8004", "agent-identity", "liveness", "trust", "web3"],
            },
        ],
        "metadata": {
            "protocol_note": (
                "This service implements the Model Context Protocol (MCP) at /mcp, not A2A's own task "
                f"methods. POST /verify-registered-agent is charged {_X402_PRICE} via x402 (Base Sepolia "
                "TESTNET, not real funds); the MCP tool is currently free -- see README. Payment settles "
                "BEFORE this handler runs: a call is charged even on AGENT_NOT_FOUND or a 422. Checks the "
                "real ERC-8004 Identity Registry on Base Sepolia testnet -- no exclusive data access, the "
                "value is the real-time MCP liveness check a raw registry lookup can't give you."
            ),
        },
    }


_NEXUS_X402_OPENAPI_OPERATIONS = [("post", "/verify-registered-agent")]


def _nexus_openapi_with_payment_info():
    if app.openapi_schema:
        return app.openapi_schema
    schema = _fastapi_get_openapi(title=app.title, version=app.version, description=app.description, routes=app.routes)
    for method, path in _NEXUS_X402_OPENAPI_OPERATIONS:
        op = schema.get("paths", {}).get(path, {}).get(method)
        if op is None:
            continue
        op["x-payment-info"] = {
            "price": {"mode": "fixed", "currency": "USD", "amount": _X402_PRICE.lstrip("$")},
            "protocols": [{"x402": {}}],
        }
        op.setdefault("responses", {})["402"] = {"description": "Payment Required"}
    schema.setdefault("info", {})["contact"] = {"email": "dasaanrod@gmail.com"}
    app.openapi_schema = schema
    return app.openapi_schema


app.openapi = _nexus_openapi_with_payment_info

app.mount("/mcp", mcp.streamable_http_app())
