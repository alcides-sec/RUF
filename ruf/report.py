"""Report generation — Markdown & JSON output."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
import re

from .models import AuditReport, Phase, Severity, Issue


def _slugify(text: str, max_len: int = 80) -> str:
    s = text.strip().lower()
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    if not s:
        s = "phase"
    return s[:max_len]


def _infer_fence_language(file_path: str) -> str:
    ext = Path(file_path).suffix.lower()
    return {
        ".sol": "solidity",
        ".vy": "python",
        ".rs": "rust",
        ".move": "move",
        ".cairo": "cairo",
        ".ts": "typescript",
        ".js": "javascript",
        ".toml": "toml",
        ".yaml": "yaml",
        ".yml": "yaml",
    }.get(ext, "")


def _read_code_snippet(
    root_path: str,
    rel_path: str,
    start_line: int,
    end_line: int,
    *,
    max_lines: int = 60,
) -> tuple[int, int, str]:
    """Return (actual_start, actual_end, snippet_text)."""
    if not root_path or not rel_path or rel_path == "unknown":
        return start_line, end_line, ""

    full = Path(root_path) / rel_path
    if not full.exists() or not full.is_file():
        return start_line, end_line, ""

    try:
        text = full.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return start_line, end_line, ""

    lines = text.splitlines()
    total = len(lines)
    if total == 0:
        return 1, 1, ""

    s = max(1, min(start_line or 1, total))
    e = max(s, min(end_line or s, total))
    if e - s + 1 > max_lines:
        e = min(s + max_lines - 1, total)

    return s, e, "\n".join(lines[s - 1 : e])


def generate_markdown(report: AuditReport) -> str:
    lines: list[str] = [
        f"# Security Audit Report: {report.project_name}",
        "",
        f"**Date:** {report.timestamp}  ",
        f"**Target:** `{report.target_path}`  ",
        f"**Auditor:** RUF AI Security Auditor  ",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        report.summary,
        "",
    ]

    confirmed = [i for i in report.issues if i.status.value == "confirmed"]
    by_sev: dict[str, int] = {}
    for i in confirmed:
        by_sev[i.severity.value] = by_sev.get(i.severity.value, 0) + 1

    lines += [
        "## Findings Overview",
        "",
        "| Severity | Count |",
        "|----------|------:|",
    ]
    for sev in Severity:
        count = by_sev.get(sev.value, 0)
        if count:
            lines.append(f"| {sev.value.upper()} | {count} |")
    lines += [f"| **TOTAL** | **{len(confirmed)}** |", ""]

    lines += [
        "## Methodology",
        "",
        "This audit was conducted using RUF's multi-pass AI pipeline:",
        "",
        "1. **Phase Planning** — codebase analysed and organised into logical audit phases.",
        "2. **Per-Phase Audit (3 passes)**:",
        "   - *Pass 1 — Discovery*: systematic identification of security issues.",
        "   - *Pass 2 — Deep Dive*: advanced attack-vector analysis.",
        "   - *Pass 3 — Validation*: false-positive elimination & severity calibration.",
        "3. **Holistic Review** — cross-phase analysis for system-level vulnerabilities.",
        "4. **Severity Validation** — skeptical re-evaluation of all ratings.",
        "",
    ]

    lines += ["## Audit Phases", ""]
    for idx, phase in enumerate(report.phases, 1):
        lines += [
            f"### Phase {idx}: {phase.name}",
            "",
            phase.description,
            "",
            f"**Files:** {', '.join(f'`{f}`' for f in phase.files)}",
            "",
            f"**Reasoning:** {phase.reasoning}",
            "",
        ]

    lines += ["## Findings", ""]

    sorted_issues = sorted(confirmed, key=lambda i: Severity.rank(i.severity))
    for issue in sorted_issues:
        title = (issue.title or "Untitled").strip()
        lines.append(f"### [{issue.severity.value.upper()}] {title}")
        lines.append("")

        # Description
        lines += ["**Description**", "", (issue.description or "").strip() or "-", ""]

        # Code location + snippet
        start = issue.line_start or 1
        # Always show meaningful context even if `line_end` is a small anchor range.
        end_hint = issue.line_end or start
        end = max(end_hint, start + 25)
        s, e, snippet = _read_code_snippet(report.root_path, issue.file_path, start, end)

        loc = f"`{issue.file_path}`"
        if issue.line_start:
            if issue.line_end:
                loc += f" (L{issue.line_start}–L{issue.line_end})"
            else:
                loc += f" (L{issue.line_start})"

        lines += ["**Code location**", "", loc, f"[data-start=\"{s}\"]"]
        fence_lang = _infer_fence_language(issue.file_path)
        lines.append(f"```{fence_lang}" if fence_lang else "```")
        if snippet:
            lines.append(snippet)
        else:
            lines.append("[snippet unavailable]")
        lines.append("```")
        lines.append("")

        # Impact
        lines += ["**Impact**", "", (issue.impact or "").strip() or "-", ""]

        # Remediation (passive language preface)
        lines.append("**Remediation**")
        lines.append("")
        rec = (issue.recommendation or "").strip()
        preface = "To mitigate this issue, the following improvements are recommended:"
        if rec:
            if rec.lower().startswith("to mitigate"):
                lines.append(rec)
            else:
                lines.append(preface)
                lines.append("")
                lines.append(rec)
        else:
            lines.append(preface)
        lines.append("")

        lines += ["---", ""]

    lines += [
        "",
        "*Report generated by [RUF AI Security Auditor](https://github.com/ruf-audit)*",
    ]
    return "\n".join(lines)


def generate_json(report: AuditReport) -> str:
    return json.dumps(report.to_dict(), indent=2)


def save_report_named(report: AuditReport, base_name: str, output_dir: str = ".") -> tuple[Path, Path]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    md_path = out / f"{base_name}.md"
    md_path.write_text(generate_markdown(report), encoding="utf-8")

    json_path = out / f"{base_name}.json"
    json_path.write_text(generate_json(report), encoding="utf-8")

    return md_path, json_path


def save_phase_report(
    project_name: str,
    target_path: str,
    root_path: str,
    phase: Phase,
    issues: list[Issue],
    output_dir: str,
    phase_index: int,
) -> tuple[Path, Path]:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    slug = _slugify(phase.name)
    base = f"ruf_phase_{phase_index:02d}_{slug}_{ts}"

    issues_list = list(issues)
    report = AuditReport(
        project_name=project_name,
        target_path=target_path,
        root_path=root_path,
        phases=[phase],
        issues=issues_list,
        summary=(
            f"Phase {phase_index}: {phase.name}. "
            f"{len(issues_list)} confirmed finding(s)."
        ),
        timestamp=datetime.now().isoformat(),
    )

    return save_report_named(report, base_name=base, output_dir=output_dir)

def save_report(report: AuditReport, output_dir: str = ".") -> tuple[Path, Path]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"ruf_audit_{report.project_name}_{ts}"
    return save_report_named(report, base_name=base, output_dir=output_dir)
