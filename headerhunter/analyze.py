"""Header classifiers.

Three categories:
  agent-directed — headers that speak to AI agents (llms.txt pointers,
      AI-crawler robots rules, x-agent-* custom headers).
  suspicious     — header VALUES containing imperative, instruction-like
      language aimed at a reader/agent. This is a POSSIBLE indirect prompt
      injection signal, NEVER a confirmed exploit. The tool detects; it
      does not exploit, and verdicts say so explicitly.
  informational  — agent-relevant but benign headers.

Everything else is left unclassified rather than guessed at.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# agent-directed detection
# ---------------------------------------------------------------------------

# Tokens identifying AI crawlers / AI data-collection bots inside
# x-robots-tag (or similar) values. Conservative list of well-documented
# bot tokens only.
AI_BOT_TOKENS = (
    "gptbot", "chatgpt-user", "oai-searchbot",
    "claudebot", "anthropic-ai",
    "ccbot", "common crawl",
    "google-extended",
    "perplexitybot",
    "bytespider",
    "cohere-ai",
    "meta-externalagent", "facebookexternalhit",
    "diffbot",
    "applebot-extended",
    "mistralai-user",
    "amazonbot",
    "imagesiftbot",
    "youbot",
)

# Known machine-readable AI-directive header names — sites publishing
# directives targeted at AI scrapers/agents through these headers.
# (Timing: Signals Corps, Oct 2026 — 217M Common Crawl responses scanned,
# 7,959 sites send AI-targeted headers, 30 attempting indirect prompt
# injection. Merged from ai-targeted-header-prober.)
AI_DIRECTIVE_NAMES = frozenset({
    "x-ai-scraper", "x-ai-agent", "x-llm-policy", "x-agent-policy",
    "x-ai-training", "x-ai-index", "ai-agent-policy",
})

# Name fragments suggesting an AI/scraper-targeted header. A header name
# containing one of these is worth reviewing for the instructions it
# carries — the channel is invisible to human visitors.
AI_NAME_FRAGMENTS = (
    "ai-agent", "ai-scraper", "scraper-directive", "agent-instruction",
    "llm-", "gpt-", "gptbot", "claude", "anthropic", "openai",
)

# Headers an agent consults that are benign on their own.
INFORMATIONAL_HEADERS = {
    "content-type",
    "content-security-policy",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "x-robots-tag",   # when it carries no AI-bot token
    "link",           # when it does not point at llms.txt
    "server",
    "x-powered-by",
}


def _is_agent_directed(name: str, value: str) -> str:
    """Return a reason string if the header is agent-directed, else ''."""
    v = value.lower()
    if name == "x-llms-txt":
        return "x-llms-txt header present (agent-readable site summary pointer)"
    if name in AI_DIRECTIVE_NAMES:
        return ("known AI-directive header name (%s) — site publishes "
                "machine-readable directives targeted at AI scrapers/agents; "
                "the channel is invisible to human visitors" % name)
    if name.startswith("x-agent-") or "ai-agent" in name:
        return "custom agent-directed header name (%s)" % name
    if any(frag in name for frag in AI_NAME_FRAGMENTS):
        return ("header name suggests AI/scraper targeting (%s) — review "
                "what instructions it carries" % name)
    if name == "x-robots-tag":
        hits = [t for t in AI_BOT_TOKENS if t in v]
        if hits:
            return "x-robots-tag names AI crawler(s): %s" % ", ".join(hits)
        return ""
    if name == "link" and "llms.txt" in v:
        return "Link header points to llms.txt"
    return ""


# ---------------------------------------------------------------------------
# suspicious (possible indirect prompt injection) detection
# ---------------------------------------------------------------------------
# Tight, documented patterns only. Each pattern targets imperative or
# instruction-smuggling language actually observed in indirect-prompt-
# injection research. Matching means "inspect manually" — nothing more.
SUSPICIOUS_PATTERNS = (
    (r"\bignore\s+(all\s+|any\s+|your\s+|the\s+|previous\s+|prior\s+)*instructions?\b",
     "tells reader to ignore instructions"),
    (r"\bdisregard\b.{0,40}\binstructions?\b",
     "tells reader to disregard instructions"),
    (r"\b(system|new)\s+instructions?\b",
     "introduces new/system instructions"),
    (r"\byou\s+are\s+now\b",
     "identity-override phrasing"),
    (r"\breveal\s+(your|the)\s+(system\s+)?prompt\b",
     "asks to reveal system prompt"),
    (r"\bexfiltrat\w*\b",
     "exfiltration language"),
    (r"\bdelete\s+(your|all\s+|the\s+)?(training\s+data|data|database|files?)\b",
     "destructive instruction toward data"),
    (r"\bexecute\b",
     "execution directive"),
    (r"\brun\s+the\s+following\b",
     "execution directive"),
    (r"\boverride\b.{0,40}\b(safety|polic\w+|guardrail|instruction)\b",
     "safety/policy override phrasing"),
    (r"\bdrop\s+table\b",
     "SQL injection fragment"),
    (r"\bunion\s+select\b",
     "SQL injection fragment"),
    (r";\s*--",
     "SQL comment-out fragment"),
    (r"\bor\s+1\s*=\s*1\b",
     "SQL tautology fragment"),
    # Merged from ai-targeted-header-prober (Signals Corps, Oct 2026):
    # hidden instruction payloads observed in the wild via header channels.
    (r"\bsend\s+(to|data|credentials?)\b",
     "data-exfiltration phrasing"),
    (r"\bcurl\b.{0,30}https?://",
     "remote shell-fetch instruction (curl pipe)"),
    (r"\bwget\b.{0,30}https?://",
     "remote shell-fetch instruction (wget)"),
)
_SUSPICIOUS_RES = [(re.compile(p, re.IGNORECASE), why)
                   for p, why in SUSPICIOUS_PATTERNS]


def _suspicious_reasons(value: str) -> list[str]:
    return [why for rx, why in _SUSPICIOUS_RES if rx.search(value)]


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------

SUSPICIOUS_VERDICT = ("suspicious — possible indirect prompt injection "
                      "(unconfirmed, inspect manually)")


def analyze(headers: dict) -> dict:
    """Classify *headers* (lowercased names) into findings.

    Returns {"findings": [...], "summary": {...}, "verdict": str}.
    A finding is {"header", "value", "category", "detail"}.
    """
    findings: list[dict] = []
    for name, value in headers.items():
        reasons = _suspicious_reasons(value)
        if reasons:
            findings.append({
                "header": name,
                "value": value,
                "category": "suspicious",
                "detail": "; ".join(reasons),
            })
            continue
        agent_reason = _is_agent_directed(name, value)
        if agent_reason:
            findings.append({
                "header": name,
                "value": value,
                "category": "agent-directed",
                "detail": agent_reason,
            })
            continue
        if name in INFORMATIONAL_HEADERS:
            findings.append({
                "header": name,
                "value": value,
                "category": "informational",
                "detail": "agent-relevant but benign",
            })

    counts = {"agent-directed": 0, "suspicious": 0, "informational": 0}
    for f in findings:
        counts[f["category"]] += 1

    if counts["suspicious"]:
        verdict = SUSPICIOUS_VERDICT
    elif counts["agent-directed"]:
        verdict = "agent-directed"
    elif counts["informational"]:
        verdict = "informational"
    else:
        verdict = "clean (no agent-relevant headers detected)"

    return {"findings": findings, "summary": counts, "verdict": verdict}
