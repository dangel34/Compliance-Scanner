"""Self-contained HTML report generator for RuleForge compliance scan results."""
from __future__ import annotations

import datetime
import html
from typing import Dict

from ui.utils import RunResult, _safe_str, compute_score, get_rule_status

_STATUS_STYLE: dict[str, tuple[str, str]] = {
    "PASS":    ("#1f6f43", "#d4edda"),
    "FAIL":    ("#721c24", "#f8d7da"),
    "PARTIAL": ("#856404", "#fff3cd"),
    "POLICY":  ("#4a2a7a", "#e8d5ff"),
    "SKIP":    ("#555e65", "#e2e3e5"),
    "ERROR":   ("#721c24", "#f8d7da"),
    "NOT_RUN": ("#333333", "#f0f0f0"),
}

_CSS = """
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
     margin:0;padding:24px;background:#f8f9fa;color:#212529}
h1{color:#1e3a5f;border-bottom:2px solid #1e3a5f;padding-bottom:8px;margin-bottom:4px}
h2{color:#1e3a5f;margin-top:24px}
.meta{color:#666;margin-bottom:20px;font-size:14px}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}
.card{padding:12px 20px;border-radius:8px;text-align:center;min-width:90px}
.card .cnt{font-size:28px;font-weight:bold}
.card .lbl{font-size:12px;margin-top:2px}
.score-wrap{background:#dee2e6;border-radius:4px;height:16px;margin-bottom:4px}
.score-bar{background:#1f6f43;border-radius:4px;height:16px}
.score-txt{font-size:13px;color:#333;margin-bottom:24px}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;
       font-size:11px;font-weight:bold;white-space:nowrap}
details{background:#fff;border:1px solid #dee2e6;border-radius:6px;
        margin-bottom:8px}
summary{padding:12px 16px;cursor:pointer;list-style:none;
        display:flex;align-items:center;gap:8px;user-select:none}
summary::-webkit-details-marker{display:none}
summary::before{content:"\\25B6";font-size:10px;color:#888;flex-shrink:0}
details[open] summary::before{content:"\\25BC"}
.checks-tbl{border-collapse:collapse;font-size:13px;
            margin:0 16px 12px 16px;width:calc(100% - 32px)}
.checks-tbl th{background:#f1f3f5;padding:6px 10px;text-align:left;
               border-bottom:1px solid #dee2e6}
.checks-tbl td{padding:6px 10px;border-bottom:1px solid #f0f0f0;vertical-align:top}
.detail{font-size:12px;color:#444}
.detail pre{background:#f8f8f8;padding:6px;border-radius:3px;overflow-x:auto;
            font-size:11px;margin:4px 0;white-space:pre-wrap;word-break:break-all}
.detail code{background:#f0f0f0;padding:1px 4px;border-radius:3px;
             font-size:11px;word-break:break-all}
"""


def _badge(status: str) -> str:
    fg, bg = _STATUS_STYLE.get(status, ("#333", "#f0f0f0"))
    return f'<span class="badge" style="color:{fg};background:{bg}">{html.escape(status)}</span>'


def generate_report_html(save_path: str, results: Dict[str, RunResult]) -> None:
    """Write a self-contained single-file HTML compliance report to *save_path*."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    counts: dict[str, int] = {s: 0 for s in ("PASS", "FAIL", "PARTIAL", "POLICY", "SKIP", "ERROR")}
    for r in results.values():
        s = get_rule_status(r)
        counts[s] = counts.get(s, 0) + 1

    score_ratio_f, score_pct = compute_score(counts["PASS"], counts["FAIL"], counts["PARTIAL"])
    automated   = counts["PASS"] + counts["FAIL"] + counts["PARTIAL"]
    score_ratio = int(score_ratio_f * 100)

    # --- summary cards ---
    cards_html = ""
    for label, key, fg, bg in [
        ("PASS",    "PASS",    "#1f6f43", "#d4edda"),
        ("FAIL",    "FAIL",    "#721c24", "#f8d7da"),
        ("PARTIAL", "PARTIAL", "#856404", "#fff3cd"),
        ("POLICY",  "POLICY",  "#4a2a7a", "#e8d5ff"),
        ("SKIP",    "SKIP",    "#555e65", "#e2e3e5"),
        ("ERROR",   "ERROR",   "#721c24", "#f8d7da"),
    ]:
        cards_html += (
            f'<div class="card" style="background:{bg};color:{fg}">'
            f'<div class="cnt">{counts[key]}</div>'
            f'<div class="lbl">{label}</div></div>'
        )

    # --- rule sections ---
    rules_html_parts: list[str] = []
    for result in results.values():
        rule_id = html.escape(_safe_str(result.get("rule_id", "")))
        title   = html.escape(_safe_str(result.get("title",   "")))
        status  = get_rule_status(result)

        check_rows = ""
        for idx, check in enumerate(result.get("checks", []), start=1):
            c_status  = _safe_str(check.get("status",         ""))
            c_name    = html.escape(_safe_str(check.get("check_name",  "")))
            cmd       = html.escape(_safe_str(check.get("command",      ""), max_len=1000))
            expected  = html.escape(_safe_str(check.get("expected_result", "")))
            rc        = check.get("returncode", "")
            stdout    = html.escape(_safe_str(check.get("stdout", ""), max_len=4000))
            stderr    = html.escape(_safe_str(check.get("stderr", ""), max_len=4000))

            detail = '<div class="detail">'
            if cmd:
                detail += f"<div><b>Command:</b> <code>{cmd}</code></div>"
            if expected:
                detail += f"<div><b>Expected:</b> {expected}</div>"
            detail += f"<div><b>Return code:</b> {rc}</div>"
            if stdout:
                detail += f"<div><b>stdout:</b><pre>{stdout}</pre></div>"
            if stderr:
                detail += f"<div><b>stderr:</b><pre>{stderr}</pre></div>"
            detail += "</div>"

            check_rows += (
                f"<tr><td>{idx}</td>"
                f"<td>{_badge(c_status)}</td>"
                f"<td>{c_name}</td>"
                f"<td>{detail}</td></tr>"
            )

        error_row = ""
        if result.get("error"):
            err_txt = html.escape(_safe_str(result["error"]))
            error_row = f'<div style="color:#721c24;padding:8px 16px;font-size:13px">Error: {err_txt}</div>'

        rules_html_parts.append(
            f"<details>"
            f"<summary>"
            f"<b>{rule_id}</b>&nbsp;&mdash;&nbsp;{title}&nbsp;&nbsp;{_badge(status)}"
            f"</summary>"
            f"{error_row}"
            f'<table class="checks-tbl">'
            f"<thead><tr><th>#</th><th>Status</th><th>Check</th><th>Details</th></tr></thead>"
            f"<tbody>{check_rows}</tbody>"
            f"</table>"
            f"</details>"
        )

    rules_html = "\n".join(rules_html_parts)

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>RuleForge Compliance Report</title>
<style>{_CSS}</style>
</head>
<body>
<h1>RuleForge Compliance Report</h1>
<div class="meta">Generated: {now} &nbsp;|&nbsp; Total rules scanned: {len(results)}</div>

<div class="cards">{cards_html}</div>

<div class="score-wrap"><div class="score-bar" style="width:{score_ratio}%"></div></div>
<div class="score-txt">
  Compliance score: <b>{score_pct}</b>
  &nbsp;({counts["PASS"]} passed, {counts["PARTIAL"]} partial of {automated} automated rules &mdash; partial counts as half credit)
</div>

<h2>Rule Results</h2>
{rules_html}
</body>
</html>
"""

    with open(save_path, "w", encoding="utf-8") as f:
        f.write(page)
