#!/usr/bin/env python3
# =============================================================================
# RGX — MCP server (stdio).  MIT licensed.
# A thin client for the hosted RGX API. All logic, payment (x402), caching and
# rate-limiting live server-side; this just forwards tool calls over HTTP.
# =============================================================================
"""
Tools:
  snap_router          task -> ranked x402 / MCP tools that serve it (Snap Router)
  token_report         pre-trade: real depth vs TVL + price corroboration + honeypot
  token_depth          largest trade that fills within 1/2/5% price impact
  price_corroboration  consensus USD price only when >=2 deep pools agree
  honeypot_check       real buy+sell round-trip; flags honeypot / transfer tax
  redeem_spread        ERC-4626 share redemption value vs market
  anomaly_screener     tokens on a chain that just broke (depth collapse / price break)

Config (env):
  RGX_API         base URL of the hosted API   (default https://rgx.example — set this)
  RGX_XPAYMENT    optional base64 x402 X-PAYMENT payload for paid calls; without it
                  the free tier applies (25 calls/day/IP)

Add to Claude:
  claude mcp add rgx -- python3 /path/to/rgx_mcp.py
  (set RGX_API in the MCP server env)
"""
from __future__ import annotations

import json
import os
import sys
import traceback

import httpx

API = os.environ.get("RGX_API", os.environ.get("RGX_TRUTH_API", "https://rgx.example")).rstrip("/")
XPAYMENT = os.environ.get("RGX_XPAYMENT", os.environ.get("RGX_TRUTH_XPAYMENT"))
PROTOCOL = "2025-06-18"
VERSION = "1.0.2"

_ADDR = {"type": "string", "pattern": "^0x[a-fA-F0-9]{40}$",
         "description": "0x-prefixed 20-byte token contract address"}
_VAULT = {"type": "string", "pattern": "^0x[a-fA-F0-9]{40}$",
          "description": "ERC-4626 vault share token address"}
_CHAIN = {"type": "string", "enum": ["base", "ethereum", "arbitrum"], "default": "base"}

# read-only, hits live on-chain state (open world), safe to retry
_READ = {"readOnlyHint": True, "destructiveHint": False,
         "idempotentHint": True, "openWorldHint": True}

# every token/vault endpoint returns this envelope
_ENVELOPE = {
    "type": "object",
    "properties": {
        "ok": {"type": "boolean", "description": "false when no hub pool / not resolvable"},
        "chain": {"type": "string"},
        "address": {"type": "string"},
        "endpoint": {"type": "string"},
        "data": {"type": "object", "description": "analysis result; shape depends on the endpoint"},
        "error": {"type": ["string", "null"]},
        "reason": {"type": ["string", "null"]},
        "retryable": {"type": ["boolean", "null"]},
        "meta": {"type": "object", "properties": {
            "elapsed_ms": {"type": "integer"}, "rpc_calls": {"type": "integer"},
            "cached": {"type": "boolean"}, "generated_at": {"type": "integer"}}},
    },
    "required": ["ok", "endpoint"],
}

TOOLS = [
    {
        "name": "snap_router",
        "title": "Snap Router — task to the right tool",
        "description": (
            "Tool/service DISCOVERY, not execution. Input: an agent task in plain words. Output: a "
            "ranked shortlist of x402 services and MCP tools from the merged x402 Bazaar + MCP "
            "Registry catalog (16k+ entries) that can do it, each with price and a 'works well "
            "with' hint. One vector pass, ~200ms, no LLM call, hybrid keyword-fill so nothing is "
            "missed. Call this FIRST, before loading candidate tools into context, whenever you do "
            "not already know which tool serves a task. NOT for on-chain token data itself (use "
            "token_report / token_depth / etc. for that). "
            "Example task: 'check a Base token for a honeypot before trading'."),
        "inputSchema": {"type": "object", "properties": {
            "task": {"type": "string", "description": "the task, in plain language"},
            "k": {"type": "integer", "default": 8, "minimum": 1, "maximum": 25,
                  "description": "how many results to return"},
            "registries": {"type": "array", "items": {"type": "string", "enum": ["x402", "mcp"]},
                           "description": "restrict to these catalogs (default: both)"},
            "max_price_usdc": {"type": "number", "description": "drop results priced above this"}},
            "required": ["task"]},
        "outputSchema": {"type": "object", "properties": {
            "task": {"type": "string"},
            "engine": {"type": "string", "enum": ["rgx-rerank", "rgx-rerank+keyword", "keyword"]},
            "picks": {"type": "array", "items": {"type": "object", "properties": {
                "name": {"type": "string"}, "type": {"type": "string", "enum": ["x402", "mcp"]},
                "resource": {"type": "string"}, "score": {"type": "number"},
                "price_usdc": {"type": ["number", "null"]}, "description": {"type": "string"}}}},
            "works_well_with": {"type": "array", "items": {"type": "string"}}},
            "required": ["task", "picks"]},
        "annotations": {"title": "Snap Router", **_READ},
    },
    {
        "name": "token_report",
        "title": "Pre-trade token report (flagship)",
        "description": (
            "The one call to make before an agent swaps into an unfamiliar ERC-20. Bundles "
            "token_depth + price_corroboration + honeypot_check in a single request that shares "
            "one pool read - cheaper and faster than the three separate calls. Returns: real "
            "tradeable depth at 1/2/5% price impact vs the headline TVL, a depth-weighted "
            "consensus price plus any dissent, and a live buy->sell honeypot / transfer-tax "
            "result. Use for pre-trade due diligence / rug check on Base, Ethereum or Arbitrum. "
            "If you need only ONE of those three signals, call that specific tool to save cost. "
            "For ERC-4626 vault shares use redeem_spread instead."),
        "inputSchema": {"type": "object", "properties": {"chain": _CHAIN, "address": _ADDR},
                        "required": ["address"]},
        "outputSchema": _ENVELOPE,
        "annotations": {"title": "Token report", **_READ},
    },
    {
        "name": "token_depth",
        "title": "Real tradeable depth vs TVL",
        "description": (
            "ONE signal: how much can actually be traded. The largest position that fills within "
            "1% / 2% / 5% price impact, measured from live on-chain quotes across every hub pool "
            "(Uniswap v3, Pancake v3, Aerodrome v2 + Slipstream), shown next to the pool's "
            "headline TVL - which routinely overstates fillable size by orders of magnitude. Use "
            "for position sizing and slippage budgeting. Does NOT judge price honesty (use "
            "price_corroboration) or sellability (use honeypot_check); for all three at once use "
            "token_report."),
        "inputSchema": {"type": "object", "properties": {"chain": _CHAIN, "address": _ADDR},
                        "required": ["address"]},
        "outputSchema": _ENVELOPE,
        "annotations": {"title": "Tradeable depth", **_READ},
    },
    {
        "name": "price_corroboration",
        "title": "Multi-pool price sanity gate",
        "description": (
            "ONE signal: is the quoted price real. Derives the token's USD price independently "
            "from each deep pool and checks they agree. Returns a consensus price ONLY when >=2 "
            "pools with genuine depth concur; otherwise flags it single-source or manipulated and "
            "lists the dissenting pools. Use as a price sanity gate before quoting, valuing a "
            "position, or trusting an oracle reading. Does NOT measure how much you can trade "
            "(use token_depth) or sellability (use honeypot_check); all three at once = "
            "token_report."),
        "inputSchema": {"type": "object", "properties": {"chain": _CHAIN, "address": _ADDR},
                        "required": ["address"]},
        "outputSchema": _ENVELOPE,
        "annotations": {"title": "Price corroboration", **_READ},
    },
    {
        "name": "honeypot_check",
        "title": "Can you sell it back",
        "description": (
            "ONE signal: sellability. Runs a real small buy then an immediate sell against the "
            "deepest pool via on-chain quotes. Flags a honeypot when the sell returns ~nothing, "
            "and reports round-trip loss beyond normal pool fees (transfer tax / sell throttle). "
            "Use right before entering a low-reputation token. Does NOT measure tradeable size "
            "(token_depth) or price honesty (price_corroboration); all three = token_report."),
        "inputSchema": {"type": "object", "properties": {"chain": _CHAIN, "address": _ADDR},
                        "required": ["address"]},
        "outputSchema": _ENVELOPE,
        "annotations": {"title": "Honeypot check", **_READ},
    },
    {
        "name": "redeem_spread",
        "title": "ERC-4626 share vs redemption value",
        "description": (
            "For ERC-4626 VAULT SHARE tokens only (sDAI, yield-vault shares, wrapped-staking "
            "tokens). Compares the share's on-chain redemption value (previewRedeem / "
            "convertToAssets) against its live secondary-market quote, and checks redeemability "
            "(paused / cooldown / cap). Use to spot a share trading above redemption (overpaying) "
            "or a stale / depegged vault. For a plain ERC-20 use token_report instead."),
        "inputSchema": {"type": "object", "properties": {"chain": _CHAIN, "address": _VAULT},
                        "required": ["address"]},
        "outputSchema": _ENVELOPE,
        "annotations": {"title": "Redeem spread", **_READ},
    },
    {
        "name": "anomaly_screener",
        "title": "What just broke on-chain",
        "description": (
            "A watch feed, not a per-token lookup. Returns tokens on a chain that JUST changed "
            "state inside the window: a corroboration break (deep pools began disagreeing), a "
            "depth collapse (real fillable liquidity fell >50%), a newly-detected honeypot, or an "
            "ERC-4626 redeem dislocation. Poll this on an interval instead of scanning tokens "
            "yourself. Filter with `signal`, widen/narrow with `since_s`. To then vet one flagged "
            "token, call token_report on it."),
        "inputSchema": {"type": "object", "properties": {
            "chain": _CHAIN,
            "signal": {"type": "string", "enum": ["corroboration_break", "depth_collapse",
                                                  "honeypot_new", "redeem_dislocation"],
                       "description": "restrict to one signal (default: all)"},
            "since_s": {"type": "integer", "default": 3600, "minimum": 60, "maximum": 86400,
                        "description": "look-back window in seconds"},
            "limit": {"type": "integer", "default": 50, "minimum": 1, "maximum": 200}},
            "required": []},
        "outputSchema": {"type": "object", "properties": {
            "chain": {"type": "string"}, "since_s": {"type": "integer"},
            "anomalies": {"type": "array", "items": {"type": "object", "properties": {
                "address": {"type": "string"}, "signal": {"type": "string"},
                "detail": {"type": "object"}, "detected_at": {"type": "integer"}}}}},
            "required": ["chain", "anomalies"]},
        "annotations": {"title": "Anomaly screener", **_READ},
    },
]


def _headers() -> dict:
    return {"X-PAYMENT": XPAYMENT} if XPAYMENT else {}


def call_tool(name: str, args: dict) -> str:
    chain = (args.get("chain") or "base").lower()
    addr = args.get("address", "")
    with httpx.Client(timeout=90) as c:
        if name == "snap_router":
            body = {k: v for k, v in {
                "task": args.get("task", ""), "k": args.get("k", 8),
                "registries": args.get("registries"),
                "max_price_usdc": args.get("max_price_usdc")}.items() if v is not None}
            r = c.post(f"{API}/v1/snap", json=body, headers=_headers())
        elif name == "anomaly_screener":
            q = {k: v for k, v in {"signal": args.get("signal"),
                                   "since_s": args.get("since_s"),
                                   "limit": args.get("limit")}.items() if v is not None}
            r = c.get(f"{API}/v1/{chain}/anomalies", params=q, headers=_headers())
        else:
            seg = "vault" if name == "redeem_spread" else "token"
            tail = {"token_report": "report", "token_depth": "depth",
                    "price_corroboration": "corroboration", "honeypot_check": "honeypot",
                    "redeem_spread": "redeem-spread"}[name]
            r = c.get(f"{API}/v1/{chain}/{seg}/{addr}/{tail}", headers=_headers())
    if r.status_code == 402:
        return json.dumps({"payment_required": True, "detail": r.json(),
                           "hint": "free tier used up; set RGX_XPAYMENT with a signed x402 payload"})
    try:
        return json.dumps(r.json(), indent=2)
    except Exception:
        return f"HTTP {r.status_code}: {r.text[:400]}"


def log(*a):
    print("[rgx-mcp]", *a, file=sys.stderr, flush=True)


def handle(msg: dict) -> dict | None:
    mid = msg.get("id")
    method = msg.get("method")
    params = msg.get("params") or {}
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": params.get("protocolVersion", PROTOCOL),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "rgx", "version": VERSION}}}
    if method in ("notifications/initialized", "initialized"):
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": mid, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}}
    if method == "tools/call":
        try:
            text = call_tool(params.get("name"), params.get("arguments") or {})
            return {"jsonrpc": "2.0", "id": mid,
                    "result": {"content": [{"type": "text", "text": text}]}}
        except Exception as e:
            log("tool error:", traceback.format_exc())
            return {"jsonrpc": "2.0", "id": mid,
                    "result": {"content": [{"type": "text", "text": f"ERROR: {e}"}], "isError": True}}
    if mid is not None:
        return {"jsonrpc": "2.0", "id": mid,
                "error": {"code": -32601, "message": f"method not found: {method}"}}
    return None


def main():
    log(f"api={API}  {'paid' if XPAYMENT else 'free-tier'}")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = handle(msg)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
