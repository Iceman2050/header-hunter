"""Terminal table and JSON report rendering."""

from __future__ import annotations

import json

CATEGORY_ORDER = ("suspicious", "agent-directed", "informational")


def _truncate(s: str, width: int) -> str:
    s = s.replace("\n", " ").replace("\r", " ")
    return s if len(s) <= width else s[: width - 1] + "…"


def render_table(result: dict) -> str:
    """Human-readable report for one scanned URL."""
    lines: list[str] = []
    lines.append("=" * 72)
    lines.append("URL:        %s" % result["url"])
    if result["final_url"] != result["url"]:
        lines.append("Final URL:  %s" % result["final_url"])
    lines.append("Status:     %s   redirects: %d"
                 % (result["status"] or "FAILED", result["redirects"]))
    if result["error"]:
        lines.append("Error:      %s" % result["error"])
    lines.append("Verdict:    %s" % result["analysis"]["verdict"])
    s = result["analysis"]["summary"]
    lines.append("Findings:   %d suspicious | %d agent-directed | %d informational"
                 % (s["suspicious"], s["agent-directed"], s["informational"]))
    lines.append("-" * 72)

    findings = result["analysis"]["findings"]
    if not findings:
        lines.append("(no agent-relevant headers detected)")
    else:
        ordered = sorted(findings,
                         key=lambda f: CATEGORY_ORDER.index(f["category"]))
        for f in ordered:
            tag = {"suspicious": "[!!]", "agent-directed": "[->]",
                   "informational": "[i]"}[f["category"]]
            lines.append("%s %-15s %s" % (tag, f["header"][:15],
                                          _truncate(f["value"], 52)))
            lines.append("     %s: %s" % (f["category"], f["detail"]))
            if f["category"] == "suspicious":
                # show the raw value verbatim so the user can inspect it
                lines.append("     raw: %r" % f["value"][:300])
    lines.append("=" * 72)
    return "\n".join(lines)


def render_json(results: list[dict]) -> str:
    """Machine-readable report: full findings, verbatim values."""
    return json.dumps({"results": results}, indent=2, ensure_ascii=False)


def result_for(url: str, fetched: dict, analysis: dict) -> dict:
    return {
        "url": fetched["url"],
        "final_url": fetched["final_url"],
        "status": fetched["status"],
        "redirects": fetched["redirects"],
        "error": fetched["error"],
        "analysis": analysis,
    }
