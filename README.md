# RGX — MCP server

<!-- mcp-name: io.github.trigeochiral/rgx -->

MCP client for **RGX**: tool discovery, reranking, and on-chain pricing-truth for
AI agents — pay-per-call in USDC on Base (x402), free tier, no signup.

Hosted API: `https://trigeochiral.com` — set it as `RGX_API`.

| Tool | What |
|---|---|
| `snap_router` | **Snap Router** — your task → the ranked x402 / MCP tools that serve it, over the merged x402 Bazaar + MCP Registry catalog (16k+). One pass, ~200ms, no LLM call. $0.003 |
| `rerank` | **RyRank** — rerank documents by relevance to a query. Cohere-compatible response shape (`results: [{index, relevance_score}]`), so it drops into an existing `co.rerank()` call. No signup, no model download. ~$0.001/call over x402 (roughly half Cohere Rerank's list price) or a free tier. |
| `vet_bounty` | **is this bounty a trap?** — screens a GitHub issue URL or raw title+body for prompt-injection / system-prompt exfiltration payloads, throwaway farm repos, no payment rail, points/token "pay", mass-recruitment dilution. Call before an agent acts on any bounty it found itself. $0.03 |
| `token_report` | pre-trade: real tradeable depth vs headline TVL + multi-pool price corroboration + honeypot test, one call. $0.04 |
| `token_depth` | largest trade that fills within 1 / 2 / 5% price impact, vs the headline TVL. $0.01 |
| `price_corroboration` | consensus USD price only when ≥2 deep pools agree; flags single-source / manipulated prices. $0.01 |
| `honeypot_check` | real buy + sell round-trip; flags honeypot / transfer tax. $0.005 |
| `redeem_spread` | ERC-4626 share redemption value vs market. $0.01 |
| `anomaly_screener` | tokens on a chain that just broke (depth collapse / price break / new honeypot). $0.025 |

Chains: `base`, `ethereum`, `arbitrum`.

## Why

- **Snap Router** — the tool-retrieval bottleneck: past ~2,000 tools, semantic
  retrieval beats keyword and beats long-context. Coinbase's Bazaar `/ask` is
  LLM-ranked (a model call on every task); 402index falls back to keyword-only
  when its embedding service times out. Snap Router has neither hole.
- **RyRank** — a hybrid reranker, not a cross-encoder: strong
  when the candidates already share vocabulary with the query, which is the
  common case for RAG retrieval output and tool/document shortlists. Built for
  high-volume, latency- and cost-sensitive reranking (narrowing a retrieval
  candidate set, deduping, triage) rather than close semantic disambiguation
  between near-identical phrasings — pay-per-call and about half the price is
  the trade for that.
- **Pricing-Truth** — every "token safety" tool checks the *contract*. None check
  whether the liquidity is real or the price is trustworthy. A pool can show
  \$15M TVL and fill \$4.

## Install

```bash
pip install rgx-mcp
claude mcp add rgx --env RGX_API=https://trigeochiral.com -- rgx-mcp
```

or with `uvx` (no install):

```bash
claude mcp add rgx --env RGX_API=https://trigeochiral.com -- uvx rgx-mcp
```

Optional: `RGX_XPAYMENT` = a base64 x402 `X-PAYMENT` payload, to make paid calls
past the free tier. Without it you get 25 free calls/day per IP.

## Direct HTTP (no MCP)

```bash
# Snap Router
curl -sX POST https://trigeochiral.com/v1/snap -H 'content-type: application/json' \
  -d '{"task":"check a base token for honeypot before trading","k":4}'

# RyRank
curl -sX POST https://trigeochiral.com/v1/rerank -H 'content-type: application/json' \
  -d '{"query":"how do I reset my password","documents":["Go to Settings > Security and click Reset Password.","Our refund policy allows returns within 30 days."],"top_n":2}'

# Pre-trade report
curl -s https://trigeochiral.com/v1/base/token/0x532f27101965dd16442E59d40670FaF5eBB142E4/report
```

Discovery: `/.well-known/agent-card.json` (A2A), `/.well-known/x402`,
`/.well-known/mcp.json`, `/llms.txt`, `/openapi.json`.

## License

MIT
