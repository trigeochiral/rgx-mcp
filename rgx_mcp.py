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

_ADDR = {"type": "string", "description": "0x-prefixed 20-byte token contract address"}
_VAULT = {"type": "string", "description": "ERC-4626 vault share token address"}
_CHAIN = {"type": "string", "enum": ["base", "ethereum", "arbitrum"], "default": "base"}

TOOLS = [
    {
        "name": "snap_router",
        "description": ("Snap Router. Give it your task in plain language; returns the ranked "
                        "shortlist of x402 services and MCP tools that serve it, from the merged "
                        "x402 Bazaar + MCP Registry catalog (16k+), plus a 'works well with' "
                        "hint. One fast pass, ~200ms, no LLM call. Call this before loading tools "
                        "into context."),
        "inputSchema": {"type": "object", "properties": {
            "task": {"type": "string", "description": "the task, in plain language"},
            "k": {"type": "integer", "default": 8},
            "registries": {"type": "array", "items": {"type": "string", "enum": ["x402", "mcp"]}},
            "max_price_usdc": {"type": "number"}},
            "required": ["task"]},
    },
    {
        "name": "token_report",
        "description": ("Pre-trade due-diligence on a DeFi token: real tradeable depth vs the "
                        "misleading headline TVL, depth-weighted price corroboration across every "
                        "pool, and a honeypot / transfer-tax check - one call. Use before an "
                        "agent swaps into any unfamiliar token."),
        "inputSchema": {"type": "object", "properties": {"chain": _CHAIN, "address": _ADDR},
                        "required": ["address"]},
    },
    {
        "name": "token_depth",
        "description": ("Largest trade that fills within 1% / 2% / 5% price impact from live "
                        "quotes across all pools, vs the headline TVL. Position sizing / is this "
                        "TVL real liquidity."),
        "inputSchema": {"type": "object", "properties": {"chain": _CHAIN, "address": _ADDR},
                        "required": ["address"]},
    },
    {
        "name": "price_corroboration",
        "description": ("Independent USD price from every deep pool, checked for agreement. "
                        "Consensus price only when >=2 pools with real depth concur; flags "
                        "single-source or manipulated prices."),
        "inputSchema": {"type": "object", "properties": {"chain": _CHAIN, "address": _ADDR},
                        "required": ["address"]},
    },
    {
        "name": "honeypot_check",
        "description": ("Real buy then immediate sell on the deepest pool. Flags a honeypot when "
                        "the sell returns nothing; reports transfer tax / sell restriction beyond "
                        "normal fees."),
        "inputSchema": {"type": "object", "properties": {"chain": _CHAIN, "address": _ADDR},
                        "required": ["address"]},
    },
    {
        "name": "redeem_spread",
        "description": ("ERC-4626 vault share: on-chain redemption value (previewRedeem / "
                        "convertToAssets) vs live market quote. Spot share mispricing / stale "
                        "vault."),
        "inputSchema": {"type": "object", "properties": {"chain": _CHAIN, "address": _VAULT},
                        "required": ["address"]},
    },
    {
        "name": "anomaly_screener",
        "description": ("Tokens on a chain that just broke: a corroboration break (deep pools "
                        "started disagreeing), a depth collapse (real fillable liquidity dropped "
                        ">50%), or a new honeypot. Poll instead of scanning tokens yourself."),
        "inputSchema": {"type": "object", "properties": {
            "chain": _CHAIN,
            "signal": {"type": "string", "enum": ["corroboration_break", "depth_collapse",
                                                  "honeypot_new", "redeem_dislocation"]},
            "since_s": {"type": "integer", "default": 3600},
            "limit": {"type": "integer", "default": 50}},
            "required": []},
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
            "serverInfo": {"name": "rgx", "version": "1.0.0"}}}
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
