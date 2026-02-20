"""Main audit pipeline — orchestrates phases, passes, and reviews."""

from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .ai_client import AIClient
from .config import Config
from .memory import AuditMemory
from .models import AuditReport, Issue, IssueStatus, Phase, Severity
from .navigator import Navigator, RESPONSES_TOOL_DEFS
from .responses_client import ResponsesAIClient
from .prompts import (
    HOLISTIC_REVIEW,
    FINAL_GLOBAL_VALIDATION,
    PASS_1_DISCOVERY,
    PASS_2_DEEP_DIVE,
    PASS_3_FALSE_POSITIVE,
    PHASE_PLANNER,
)
from .report import save_report, save_phase_report

console = Console()


@dataclass(frozen=True)
class PhaseSession:
    """Per-phase Responses API session state."""

    response_id: str


class AuditPipeline:
    def __init__(self, target_path: str, config: Config, output_dir: str = "./audit_reports") -> None:
        target = Path(target_path).resolve()

        self.target_path = str(target)
        self.config = config
        self.output_dir = output_dir

        self.scope_files: list[str] | None = None
        if target.is_file():
            root = _detect_project_root(target)
            self.root_path = str(root)
            try:
                self.scope_files = [str(target.relative_to(root))]
            except ValueError:
                self.root_path = str(target.parent)
                self.scope_files = [target.name]
        else:
            self.root_path = str(target)

        self.navigator = Navigator(self.root_path, config)
        self.ai = AIClient(config, self.navigator)
        self.memory = AuditMemory()

    # ==================================================================
    # Top-level entry point
    # ==================================================================

    def run(self) -> AuditReport:
        console.print(
            Panel.fit(
                "[bold]RUF — AI Security Auditor[/bold]\n"
                f"Target: {self.target_path}\n"
                f"Root:   {self.root_path}\n"
                f"Model:  {self.config.model}",
                border_style="blue",
            )
        )

        self._scan_project()
        self._plan_phases()
        selected_phases, parallelism = self._prompt_phase_settings()
        self._execute_phases_in_parallel_waves(selected_phases, parallelism)

        self._final_global_validation()
        self._auto_save("after-final")

        return self._build_report()

    # ==================================================================
    # Helpers
    # ==================================================================

    def _get_audit_file_paths(self) -> list[str]:
        return self.scope_files or self.navigator.get_all_file_paths()

    def _auto_save(self, tag: str) -> None:
        """Save a partial report so progress is never lost on a crash."""
        try:
            partial = self._build_report()
            partial.summary = f"[PARTIAL \u2014 {tag}] {partial.summary}"
            md_path, json_path = save_report(partial, self.output_dir)
            console.print(
                f"  [dim]Auto-saved progress ({tag}): {md_path.name}[/dim]"
            )
        except Exception as exc:
            console.print(f"  [yellow]Auto-save failed: {exc}[/yellow]")

    def _save_checkpoint(self, tag: str, data: dict) -> None:
        """Save raw intermediate results (pass outputs) to disk."""
        try:
            out = Path(self.output_dir)
            out.mkdir(parents=True, exist_ok=True)
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            path = out / f"ruf_checkpoint_{tag}_{ts}.json"
            path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
            console.print(f"  [dim]Checkpoint saved: {path.name}[/dim]")
        except Exception as exc:
            console.print(f"  [yellow]Checkpoint save failed: {exc}[/yellow]")

    def _prompt_phase_settings(self) -> tuple[list[Phase], int]:
        """Ask the user which phases to audit and how much parallelism to use."""
        phases = self.memory.phases
        if not phases:
            return [], 1

        console.print("\n[bold]Select phases to audit[/bold]")
        console.print("Enter phase numbers separated by spaces (e.g. `1 3 5`).")
        console.print("Press Enter to audit all phases.")

        try:
            raw = input("Phases> ").strip()
        except EOFError:
            raw = ""

        if not raw or raw.lower() == "all":
            indices = list(range(1, len(phases) + 1))
        else:
            indices: list[int] = []
            for tok in raw.split():
                if tok.isdigit():
                    idx = int(tok)
                    if 1 <= idx <= len(phases) and idx not in indices:
                        indices.append(idx)
            if not indices:
                indices = list(range(1, len(phases) + 1))

        console.print("\n[bold]Parallelism[/bold]")
        console.print("How many phases to audit in parallel? (min 1, max 4)")
        try:
            raw_p = input("Parallelism (1-4)> ").strip()
        except EOFError:
            raw_p = ""

        parallelism = 2
        if raw_p:
            try:
                parallelism = int(raw_p)
            except ValueError:
                parallelism = 2
        parallelism = max(1, min(4, parallelism))

        selected = [phases[i - 1] for i in indices]
        console.print(
            f"\n[dim]Selected phases: {' '.join(str(i) for i in indices)} | "
            f"Parallelism: {parallelism}[/dim]"
        )
        return selected, parallelism

    def _execute_phases_in_parallel_waves(self, phases: list[Phase], parallelism: int) -> None:
        """Run pass 1 for all phases, then pass 2 for all, then pass 3 for all."""
        if not phases:
            console.print("\n[yellow]No phases selected — skipping per-phase audit.[/yellow]")
            return

        console.print(
            f"\n[dim]Running {len(phases)} phase(s) with parallelism={parallelism}[/dim]"
        )

        # Wave Pass 1 — Discovery
        _section("Wave Pass 1/3 — Discovery (all selected phases)", "green")
        pass1, pass1_sessions = self._run_wave_pass(
            phases=phases,
            prompt_tpl=PASS_1_DISCOVERY,
            pass_num=1,
            previous_map=None,
            previous_sessions=None,
            include_code=True,
            parallelism=parallelism,
        )
        self._save_checkpoint(
            "pass1_discovery",
            {k: [i.to_dict() for i in v] for k, v in pass1.items()},
        )

        # Wave Pass 2 — Deep Dive
        _section("Wave Pass 2/3 — Deep Dive (all selected phases)", "green")
        pass2, pass2_sessions = self._run_wave_pass(
            phases=phases,
            prompt_tpl=PASS_2_DEEP_DIVE,
            pass_num=2,
            previous_map=pass1,
            previous_sessions=pass1_sessions,
            include_code=False,
            parallelism=parallelism,
        )
        self._save_checkpoint(
            "pass2_deep_dive",
            {k: [i.to_dict() for i in v] for k, v in pass2.items()},
        )

        # Wave Pass 3 — Validation (false-positive pruning)
        _section("Wave Pass 3/3 — Validation (all selected phases)", "green")
        validated, _validated_sessions = self._run_wave_validation(
            phases=phases,
            pass1=pass1,
            pass2=pass2,
            previous_sessions=pass2_sessions,
            parallelism=parallelism,
        )
        self._save_checkpoint(
            "pass3_validated",
            {k: [i.to_dict() for i in v] for k, v in validated.items()},
        )

        # Merge validated results into memory in a stable order
        for idx, phase in enumerate(phases, 1):
            p1 = pass1.get(phase.name, [])
            p2 = pass2.get(phase.name, [])
            combined = p1 + p2
            final = validated.get(phase.name, [])

            confirmed = [i for i in final if i.status == IssueStatus.CONFIRMED]
            pruned = max(len(combined) - len(confirmed), 0)

            console.print(
                f"\n[bold yellow]Phase {idx}/{len(phases)}: {phase.name}[/bold yellow]"
            )
            console.print(
                f"  [dim]Confirmed: {len(confirmed)} | "
                f"Eliminated: {pruned} | Candidates: {len(combined)}[/dim]"
            )

            self.memory.add_issues(final)
            self.memory.add_phase_summary(
                phase.name,
                f"Confirmed {len(confirmed)} issue(s) from {len(combined)} candidates.",
            )

            self._auto_save(f"after-phase-{idx}")

    def _run_wave_pass(
        self,
        phases: list[Phase],
        prompt_tpl: str,
        pass_num: int,
        previous_map: dict[str, list[Issue]] | None,
        previous_sessions: dict[str, PhaseSession] | None,
        include_code: bool,
        parallelism: int,
    ) -> tuple[dict[str, list[Issue]], dict[str, PhaseSession]]:
        ctx = self.memory.get_context_summary()
        results: dict[str, list[Issue]] = {}
        sessions: dict[str, PhaseSession] = {}

        with ThreadPoolExecutor(max_workers=parallelism) as executor:
            futures = {}
            for phase in phases:
                prev = previous_map.get(phase.name) if previous_map else None
                prev_sess = previous_sessions.get(phase.name) if previous_sessions else None
                futures[
                    executor.submit(
                        self._run_pass_for_phase,
                        ctx,
                        prompt_tpl,
                        phase,
                        pass_num,
                        prev,
                        prev_sess,
                        include_code,
                    )
                ] = phase

            for fut in as_completed(futures):
                phase = futures[fut]
                try:
                    issues, sess = fut.result()
                except Exception as exc:
                    console.print(f"[red]Phase '{phase.name}' pass {pass_num} failed: {exc}[/red]")
                    issues = []
                    sess = previous_sessions.get(phase.name) if previous_sessions else None
                results[phase.name] = issues
                if sess and sess.response_id:
                    sessions[phase.name] = sess
                console.print(f"  [dim]Completed {phase.name}: {len(issues)} finding(s)[/dim]")
                if issues:
                    console.print(f"  [yellow]Unvalidated candidates (pass {pass_num}) — {phase.name}[/yellow]")
                    _display_issues(issues, f"{phase.name} Pass {pass_num} Candidates (UNVALIDATED)")

        return results, sessions

    def _run_wave_validation(
        self,
        phases: list[Phase],
        pass1: dict[str, list[Issue]],
        pass2: dict[str, list[Issue]],
        previous_sessions: dict[str, PhaseSession] | None,
        parallelism: int,
    ) -> tuple[dict[str, list[Issue]], dict[str, PhaseSession]]:
        ctx = self.memory.get_context_summary()
        results: dict[str, list[Issue]] = {}
        sessions: dict[str, PhaseSession] = {}
        phase_index = {p.name: i + 1 for i, p in enumerate(phases)}

        with ThreadPoolExecutor(max_workers=parallelism) as executor:
            futures = {}
            for phase in phases:
                combined = pass1.get(phase.name, []) + pass2.get(phase.name, [])
                prev_sess = previous_sessions.get(phase.name) if previous_sessions else None
                futures[
                    executor.submit(self._run_validation_for_phase, ctx, phase, combined, prev_sess)
                ] = phase

            for fut in as_completed(futures):
                phase = futures[fut]
                try:
                    issues, sess = fut.result()
                except Exception as exc:
                    console.print(f"[red]Phase '{phase.name}' validation failed: {exc}[/red]")
                    issues = []
                    sess = previous_sessions.get(phase.name) if previous_sessions else None
                results[phase.name] = issues
                if sess and sess.response_id:
                    sessions[phase.name] = sess
                console.print(f"  [dim]Validated {phase.name}: {len(issues)} confirmed finding(s)[/dim]")
                if issues:
                    _display_issues(issues, f"{phase.name} Validated Findings")

                # Save per-phase report immediately after validation completes
                try:
                    out_dir = str(Path(self.output_dir) / "phase_reports")
                    save_phase_report(
                        project_name=Path(self.root_path).name,
                        target_path=self.target_path,
                        root_path=self.root_path,
                        phase=phase,
                        issues=issues,
                        output_dir=out_dir,
                        phase_index=phase_index.get(phase.name, 0) or 0,
                    )
                except Exception as exc:
                    console.print(f"[yellow]Phase report save failed ({phase.name}): {exc}[/yellow]")

        return results, sessions

    def _run_pass_for_phase(
        self,
        ctx: str,
        prompt_tpl: str,
        phase: Phase,
        pass_num: int,
        previous_findings: list[Issue] | None,
        previous_session: PhaseSession | None,
        include_code: bool,
    ) -> tuple[list[Issue], PhaseSession | None]:
        """Run a single pass for a single phase (worker-safe)."""
        nav = Navigator(self.root_path, self.config)
        ai = ResponsesAIClient(self.config, nav)

        prev_id = previous_session.response_id if previous_session else None
        cache_key = f"ruf:{Path(self.root_path).name}:{self.config.model}:{_slug_key(phase.name)}"

        prev_text = (
            "None — this is the first pass."
            if not previous_findings
            else json.dumps([i.to_dict() for i in previous_findings], separators=(",", ":"))
        )

        prompt = prompt_tpl.format(
            context=ctx,
            phase_name=phase.name,
            phase_description=phase.description,
            file_list=", ".join(phase.files),
            dependencies=", ".join(phase.dependencies) or "None",
            previous_findings=prev_text,
            all_findings=prev_text,
        )
        prompt = (
            "Execution note:\n"
            "- Phase source files are provided as plain text (either in this message or earlier in this session).\n"
            "- Base findings strictly on that provided code; avoid requesting additional reads.\n\n"
            "- For every finding, include `code_anchor` (2–5 consecutive verbatim lines from the file near the issue, including at least one likely-unique line) so the pipeline can compute exact line numbers.\n\n"
            + prompt
        )

        must_include_code = include_code or not prev_id
        if must_include_code:
            file_sections: list[str] = []
            for f in phase.files:
                result = nav.read_file_plain(f)
                if "error" in result:
                    file_sections.append(f"### {f} (read error)\n```\n{result['error']}\n```")
                else:
                    file_sections.append(
                        f"### {f} ({result['total_lines']} lines)\n"
                        f"```\n{result['content']}\n```"
                    )
            user_msg = (
                f"Begin your analysis of phase: {phase.name}\n\n"
                f"## Source Files (pre-loaded — all {len(phase.files)} files)\n\n"
                + "\n\n".join(file_sections)
            )
        else:
            outline_sections: list[str] = []
            OUTLINE_MAX_LINES = 200
            for f in phase.files:
                out = nav.get_file_outline(f)
                if "error" in out:
                    outline_sections.append(f"### {f} (outline error)\n```\n{out['error']}\n```")
                else:
                    raw = (out.get("outline", "") or "").splitlines()
                    clipped = "\n".join(raw[:OUTLINE_MAX_LINES])
                    outline_sections.append(
                        f"### {f} (outline)\n```\n{clipped}\n```"
                    )
            user_msg = (
                f"Continue pass {pass_num} for phase: {phase.name}\n\n"
                "The full phase source files were provided earlier in this session.\n\n"
                "## File outlines (for quick navigation; do not re-request full files)\n\n"
                + "\n\n".join(outline_sections)
            )

        report_tool = next(t for t in RESPONSES_TOOL_DEFS if t.get("name") == "report_findings")
        cache_retention = getattr(self.config, "prompt_cache_retention", "24h")

        eff = "xhigh" if pass_num == 1 else "high"
        verb = self.config.verbosity

        result = ai.execute(
            prompt,
            user_msg,
            previous_response_id=prev_id,
            tools=[report_tool],
            tool_choice={"type": "function", "name": "report_findings"},
            prompt_cache_key=cache_key,
            prompt_cache_retention=cache_retention,
            model=self.config.model,
            reasoning_effort=eff,
            verbosity=verb,
        )
        _log_api_metrics(
            stage=f"phase-pass-{pass_num}",
            phase=phase.name,
            model=self.config.model,
            reasoning_effort=eff,
            verbosity=verb,
            result=result,
        )

        issues = _parse_findings(
            result.get("findings", []),
            pass_num,
            phase.name,
            root_path=self.root_path,
        )
        new_id = str(result.get("response_id", "") or prev_id or "")
        sess = PhaseSession(response_id=new_id) if new_id else None
        return issues, sess

    def _run_validation_for_phase(
        self,
        ctx: str,
        phase: Phase,
        issues: list[Issue],
        previous_session: PhaseSession | None,
    ) -> tuple[list[Issue], PhaseSession | None]:
        nav = Navigator(self.root_path, self.config)
        ai = ResponsesAIClient(self.config, nav)

        prev_id = previous_session.response_id if previous_session else None
        cache_key = f"ruf:{Path(self.root_path).name}:{self.config.model}:{_slug_key(phase.name)}"

        issues_json = json.dumps([i.to_dict() for i in issues], separators=(",", ":"))
        prompt = PASS_3_FALSE_POSITIVE.format(
            context=ctx,
            all_findings=issues_json,
            phase_name=phase.name,
            file_list=", ".join(phase.files),
        )
        prompt = (
            "Execution note:\n"
            "- Phase source files are provided as plain text (either in this message or earlier in this session).\n"
            "- Base validation strictly on that provided code; avoid requesting additional reads.\n\n"
            "- For every finding, include `code_anchor` (2–5 consecutive verbatim lines from the file near the issue, including at least one likely-unique line) so the pipeline can compute exact line numbers.\n\n"
            + prompt
        )

        must_include_code = not prev_id
        if must_include_code:
            file_sections: list[str] = []
            for f in phase.files:
                result = nav.read_file_plain(f)
                if "error" in result:
                    file_sections.append(f"### {f} (read error)\n```\n{result['error']}\n```")
                else:
                    file_sections.append(
                        f"### {f} ({result['total_lines']} lines)\n"
                        f"```\n{result['content']}\n```"
                    )
            user_msg = (
                f"Validate findings for phase: {phase.name}\n\n"
                f"## Source Files (pre-loaded — all {len(phase.files)} files)\n\n"
                + "\n\n".join(file_sections)
            )
        else:
            # Provide targeted snippets to keep validation quality high without
            # re-sending the full phase code.
            snippet_sections: list[str] = []
            SNIPPET_PAD = 10
            SNIPPET_MAX_LINES = 80

            ranges_by_file: dict[str, list[tuple[int, int]]] = {}
            for iss in issues:
                fp = (iss.file_path or "").strip()
                if not fp or fp == "unknown":
                    continue
                ls = iss.line_start or 1
                le = iss.line_end or ls
                s = max(1, ls - SNIPPET_PAD)
                e = le + SNIPPET_PAD
                if (e - s + 1) > SNIPPET_MAX_LINES:
                    e = s + SNIPPET_MAX_LINES - 1
                ranges_by_file.setdefault(fp, []).append((s, e))

            def _merge_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
                merged: list[list[int]] = []
                for s, e in sorted(ranges):
                    if not merged or s > merged[-1][1] + 1:
                        merged.append([s, e])
                    else:
                        merged[-1][1] = max(merged[-1][1], e)
                return [(a, b) for a, b in merged]

            for fp in sorted(ranges_by_file.keys()):
                for s, e in _merge_ranges(ranges_by_file[fp]):
                    snippet = nav.read_file_plain(fp, s, e)
                    if "error" in snippet:
                        snippet_sections.append(
                            f"### {fp} ({s}-{e}) (read error)\n```\n{snippet['error']}\n```"
                        )
                    else:
                        snippet_sections.append(
                            f"### {fp} ({snippet.get('showing', f'{s}-{e}')})\n"
                            f"```\n{snippet.get('content','')}\n```"
                        )

            user_msg = (
                f"Validate findings for phase: {phase.name}\n\n"
                f"## Relevant code snippets (do not re-request full files)\n\n"
                + ("\n\n".join(snippet_sections) if snippet_sections else "[No snippets could be extracted]")
            )

        report_tool = next(t for t in RESPONSES_TOOL_DEFS if t.get("name") == "report_findings")
        cache_retention = getattr(self.config, "prompt_cache_retention", "24h")

        eff = "high"
        verb = self.config.verbosity

        result = ai.execute(
            prompt,
            user_msg,
            previous_response_id=prev_id,
            tools=[report_tool],
            tool_choice={"type": "function", "name": "report_findings"},
            prompt_cache_key=cache_key,
            prompt_cache_retention=cache_retention,
            model=self.config.model,
            reasoning_effort=eff,
            verbosity=verb,
        )
        _log_api_metrics(
            stage="phase-validation",
            phase=phase.name,
            model=self.config.model,
            reasoning_effort=eff,
            verbosity=verb,
            result=result,
        )

        parsed = _parse_findings(
            result.get("findings", []),
            3,
            phase.name,
            root_path=self.root_path,
        )
        new_id = str(result.get("response_id", "") or prev_id or "")
        sess = PhaseSession(response_id=new_id) if new_id else None
        return parsed, sess

    # ==================================================================
    # Step 1 — Scan
    # ==================================================================

    def _scan_project(self) -> None:
        console.print("\n[bold blue]▸ Scanning project structure…[/bold blue]")
        self.memory.file_tree = self.navigator.get_file_tree()
        files = self._get_audit_file_paths()
        console.print(f"  Found [cyan]{len(files)}[/cyan] auditable files\n")
        console.print(self.memory.file_tree)

        if self.scope_files:
            console.print("\n[dim]Scoped audit files:[/dim]")
            for f in self.scope_files:
                console.print(f"  [dim]- {f}[/dim]")

    # ==================================================================
    # Step 2 — Phase planning
    # ==================================================================

    def _plan_phases(self) -> None:
        console.print("\n[bold blue]▸ Planning audit phases…[/bold blue]")

        files = self._get_audit_file_paths()
        allowed = set(files)
        line_counts = self.navigator.get_line_counts(files)

        previews: list[str] = []
        for f in files[:60]:
            result = self.navigator.read_file_plain(f, 1, 40)
            if "error" not in result:
                previews.append(f"### {f}\n```\n{result['content']}\n```")

        user_msg = (
            f"## Project Structure\n```\n{self.memory.file_tree}\n```\n\n"
            f"## Audit Scope Files ({len(files)})\n" + "\n".join(files) + "\n\n"
            f"## File Previews (first 40 lines)\n" + "\n\n".join(previews)
        )

        # Phase planning is a "navigation" task; use the faster navigation model settings.
        planner_cfg = replace(
            self.config,
            model=self.config.navigation_model,
            reasoning_effort=self.config.navigation_reasoning_effort,
            verbosity=self.config.navigation_verbosity,
        )
        planner_ai = AIClient(planner_cfg, self.navigator)
        data = planner_ai.execute_json(PHASE_PLANNER, user_msg)

        phases: list[Phase] = []
        assigned: set[str] = set()
        for p in data.get("phases", []):
            raw_files = p.get("files", [])
            if not isinstance(raw_files, list):
                raw_files = []
            phase_files: list[str] = []
            seen: set[str] = set()
            for f in raw_files:
                if f in allowed and f not in seen:
                    phase_files.append(f)
                    seen.add(f)
                    assigned.add(f)
            if not phase_files:
                continue
            phases.append(
                Phase(
                    name=p.get("name", "Unnamed Phase"),
                    description=p.get("description", ""),
                    reasoning=p.get("reasoning", ""),
                    files=phase_files,
                    dependencies=p.get("dependencies", []),
                )
            )

        # Ensure 100% file coverage (planner quality must never cause misses).
        missing = [f for f in files if f not in assigned]
        if missing:
            phases.append(
                Phase(
                    name="Remaining / Unassigned Files",
                    description="Files not assigned by the planner; included to guarantee full audit coverage.",
                    reasoning="Added automatically to prevent audit scope gaps.",
                    files=missing,
                    dependencies=[],
                )
            )

        if not phases:
            phases = [
                Phase(
                    name="Full Scope (Planner Fallback)",
                    description="Planner returned no phases; auditing the full scope as a fallback.",
                    reasoning="Added automatically so the audit always runs.",
                    files=files,
                    dependencies=[],
                )
            ]

        # Auto-split oversized phases to reduce context overflow risk.
        MAX_PHASE_FILES = 25
        MAX_PHASE_LINES = 6000

        def _split_phase(ph: Phase) -> list[Phase]:
            total_lines = sum(line_counts.get(f, 0) for f in ph.files)
            if len(ph.files) <= MAX_PHASE_FILES and total_lines <= MAX_PHASE_LINES:
                return [ph]

            chunks: list[list[str]] = []
            cur: list[str] = []
            cur_lines = 0
            for f in ph.files:
                lines = line_counts.get(f, 0)
                if cur and (len(cur) >= MAX_PHASE_FILES or (cur_lines + lines) > MAX_PHASE_LINES):
                    chunks.append(cur)
                    cur = [f]
                    cur_lines = lines
                else:
                    cur.append(f)
                    cur_lines += lines
            if cur:
                chunks.append(cur)

            if len(chunks) <= 1:
                return [ph]

            out: list[Phase] = []
            for i, chunk in enumerate(chunks, 1):
                out.append(
                    Phase(
                        name=f"{ph.name} (Part {i}/{len(chunks)})",
                        description=ph.description,
                        reasoning=(ph.reasoning + " (Auto-split to fit model context.)").strip(),
                        files=chunk,
                        dependencies=ph.dependencies,
                    )
                )
            return out

        split: list[Phase] = []
        for ph in phases:
            split.extend(_split_phase(ph))
        phases = split

        self.memory.phases = phases

        tbl = Table(title="Audit Phases", show_lines=True)
        tbl.add_column("#", style="bold", width=3)
        tbl.add_column("Phase", style="cyan")
        tbl.add_column("Files", style="green", justify="right")
        tbl.add_column("Description")
        tbl.add_column("Reasoning", style="dim", max_width=60)

        for i, p in enumerate(phases, 1):
            tbl.add_row(
                str(i),
                p.name,
                str(len(p.files)),
                p.description,
                p.reasoning[:120] + ("…" if len(p.reasoning) > 120 else ""),
            )
        console.print(tbl)

        strategy = data.get("overall_strategy", "")
        if strategy:
            console.print(f"\n[dim]Strategy: {strategy}[/dim]")

        console.print("\n[bold]Phase file lists[/bold]")
        for i, p in enumerate(phases, 1):
            console.print(f"\n[cyan]{i}. {p.name}[/cyan]")
            for f in p.files:
                console.print(f"  - {f}")

    # ==================================================================
    # Step 3 — Per-phase multi-pass audit
    # ==================================================================

    def _execute_phase(self, phase_num: int, phase: Phase) -> None:
        _section(f"Phase {phase_num}/{len(self.memory.phases)}: {phase.name}", "yellow")
        console.print(f"  [dim]{phase.description}[/dim]")
        console.print(f"  [dim]Files: {', '.join(phase.files)}[/dim]\n")

        # --- Pass 1: Discovery ---
        console.print("[bold green]  ▸ Pass 1/3 — Discovery[/bold green]")
        p1_issues = self._run_audit_pass(
            PASS_1_DISCOVERY, phase, pass_num=1, previous_findings=None,
        )
        console.print(f"    [green]Found {len(p1_issues)} issues[/green]")

        # --- Pass 2: Deep dive ---
        console.print("\n[bold green]  ▸ Pass 2/3 — Deep Dive[/bold green]")
        p2_issues = self._run_audit_pass(
            PASS_2_DEEP_DIVE, phase, pass_num=2, previous_findings=p1_issues,
        )
        console.print(f"    [green]Found {len(p2_issues)} additional issues[/green]")

        combined = p1_issues + p2_issues

        # --- Pass 3: Prune false positives ---
        console.print("\n[bold green]  ▸ Pass 3/3 — False-Positive Elimination[/bold green]")
        validated = self._run_pruning_pass(phase, combined)

        confirmed = [i for i in validated if i.status == IssueStatus.CONFIRMED]
        pruned = len(combined) - len(confirmed)
        console.print(
            f"    [green]{len(confirmed)} confirmed, {pruned} eliminated[/green]"
        )

        self.memory.add_issues(validated)
        self.memory.add_phase_summary(
            phase.name,
            f"Found {len(confirmed)} confirmed issues from {len(combined)} candidates.",
        )

        _display_issues(confirmed, f"Phase {phase_num} Results")

    # ------------------------------------------------------------------

    def _run_audit_pass(
        self,
        prompt_tpl: str,
        phase: Phase,
        pass_num: int,
        previous_findings: list[Issue] | None,
    ) -> list[Issue]:
        ctx = self.memory.get_context_summary()
        prev_text = (
            "None \u2014 this is the first pass."
            if not previous_findings
            else json.dumps([i.to_dict() for i in previous_findings], separators=(",", ":"))
        )

        prompt = prompt_tpl.format(
            context=ctx,
            phase_name=phase.name,
            phase_description=phase.description,
            file_list=", ".join(phase.files),
            dependencies=", ".join(phase.dependencies) or "None",
            previous_findings=prev_text,
            all_findings=prev_text,
        )

        # Pre-load ALL phase files into the user message so they are always
        # in context and can never be pruned away.  This prevents the
        # read-prune-reread loop that was causing 0-finding passes.
        file_sections: list[str] = []
        required_reads = self.navigator.get_line_counts(phase.files)
        for f in phase.files:
            result = self.navigator.read_file_plain(f)
            if "error" not in result:
                file_sections.append(
                    f"### {f} ({result['total_lines']} lines)\n"
                    f"```\n{result['content']}\n```"
                )

        user_msg = (
            f"Begin your analysis of phase: {phase.name}\n\n"
            f"## Source Files (pre-loaded \u2014 all {len(phase.files)} files)\n\n"
            + "\n\n".join(file_sections)
        )

        result = self.ai.execute(
            prompt,
            user_msg,
            required_reads=required_reads,
            pre_read_paths=set(phase.files),
        )

        issues = _parse_findings(
            result.get("findings", []),
            pass_num,
            phase.name,
            root_path=self.root_path,
        )

        if result.get("analysis_summary"):
            self.memory.add_observation(
                f"[{phase.name} Pass {pass_num}] {result['analysis_summary']}"
            )

        return issues

    def _run_pruning_pass(self, phase: Phase, issues: list[Issue]) -> list[Issue]:
        ctx = self.memory.get_context_summary()
        issues_json = json.dumps([i.to_dict() for i in issues], separators=(",", ":"))

        prompt = PASS_3_FALSE_POSITIVE.format(
            context=ctx,
            all_findings=issues_json,
            phase_name=phase.name,
            file_list=", ".join(phase.files),
        )

        result = self.ai.execute(
            prompt, f"Review and validate findings for phase: {phase.name}",
        )

        validated = _parse_findings(
            result.get("findings", []),
            3,
            phase.name,
            root_path=self.root_path,
        )

        return validated if validated else issues

    # ==================================================================
    # Step 4 — Holistic cross-phase review
    # ==================================================================

    def _holistic_review(self) -> None:
        _section("Holistic Review — Cross-Phase Analysis", "magenta")

        ctx = self.memory.get_context_summary()
        confirmed = self.memory.get_confirmed_issues()
        issues_json = json.dumps([i.to_dict() for i in confirmed], separators=(",", ":"))

        prompt = HOLISTIC_REVIEW.format(
            context=ctx,
            all_issues=issues_json,
            file_tree=self.memory.file_tree,
            all_files=f"(total {len(self._get_audit_file_paths())} files; see file tree above)",
        )

        nav = Navigator(self.root_path, self.config)
        ai = ResponsesAIClient(self.config, nav)
        report_tool = next(t for t in RESPONSES_TOOL_DEFS if t.get("name") == "report_findings")
        cache_key = f"ruf:{Path(self.root_path).name}:{self.config.model}:holistic"
        result = ai.execute(
            prompt,
            "Perform holistic review of the complete audit.",
            model=self.config.model,
            reasoning_effort="medium",
            verbosity="medium",
            tools=[report_tool],
            tool_choice={"type": "function", "name": "report_findings"},
            prompt_cache_key=cache_key,
            prompt_cache_retention=self.config.prompt_cache_retention,
            max_turns=min(getattr(self.config, "max_tool_iterations", 80), 60),
        )
        _log_api_metrics(
            stage="holistic",
            phase="holistic-review",
            model=self.config.model,
            reasoning_effort="medium",
            verbosity="medium",
            result=result,
        )

        new_issues = _parse_findings(
            result.get("findings", []),
            pass_num=4,
            phase_name="holistic-review",
            root_path=self.root_path,
        )

        if new_issues:
            self.memory.add_issues(new_issues)
            console.print(
                f"  [magenta]Found {len(new_issues)} additional cross-phase issues[/magenta]"
            )
            _display_issues(new_issues, "Holistic Review Findings")
        else:
            console.print("  [dim]No additional cross-phase issues found.[/dim]")

    # ==================================================================
    # Step 5 — Final global validation (dedup + false positives)
    # ==================================================================

    def _final_global_validation(self) -> None:
        _section("Final Review — Cross-Phase + Skeptical Validation", "red")

        candidates = self.memory.get_confirmed_issues()
        if not candidates:
            console.print("  [dim]No findings to validate.[/dim]")
            return

        ctx = self.memory.get_context_summary()
        candidates_json = json.dumps([i.to_dict() for i in candidates], separators=(",", ":"))

        # Build grounded snippets for every candidate finding to reduce hallucinations.
        nav = Navigator(self.root_path, self.config)
        snippet_sections: list[str] = []

        SNIPPET_PAD = 15
        SNIPPET_MAX_LINES = 120

        ranges_by_file: dict[str, list[tuple[int, int]]] = {}
        for iss in candidates:
            fp = (iss.file_path or "").strip()
            if not fp or fp == "unknown":
                continue
            ls = iss.line_start or 1
            le = iss.line_end or max(ls, (ls + 25))
            s = max(1, ls - SNIPPET_PAD)
            e = le + SNIPPET_PAD
            if (e - s + 1) > SNIPPET_MAX_LINES:
                e = s + SNIPPET_MAX_LINES - 1
            ranges_by_file.setdefault(fp, []).append((s, e))

        def _merge_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
            merged: list[list[int]] = []
            for s, e in sorted(ranges):
                if not merged or s > merged[-1][1] + 1:
                    merged.append([s, e])
                else:
                    merged[-1][1] = max(merged[-1][1], e)
            return [(a, b) for a, b in merged]

        for fp in sorted(ranges_by_file.keys()):
            for s, e in _merge_ranges(ranges_by_file[fp]):
                snippet = nav.read_file_plain(fp, s, e)
                if "error" in snippet:
                    snippet_sections.append(
                        f"### {fp} ({s}-{e})\n```\n{snippet['error']}\n```"
                    )
                else:
                    snippet_sections.append(
                        f"### {fp} ({snippet.get('showing', f'{s}-{e}')})\n"
                        f"```\n{snippet.get('content','')}\n```"
                    )

        snippets_text = "\n\n".join(snippet_sections) if snippet_sections else "[no snippets available]"
        prompt = FINAL_GLOBAL_VALIDATION.format(
            context=ctx,
            all_findings=candidates_json,
            snippets=snippets_text,
        )
        prompt = (
            "Execution note:\n"
            "- You may use tools to confirm missing cross-phase issues. Keep tool turns minimal and batch work.\n"
            "- Prefer `search_files_multi` and `read_files` to reduce round trips.\n"
            "- Only report issues you can support with code. Always include `code_anchor`.\n\n"
            + prompt
        )

        ai = ResponsesAIClient(self.config, nav)
        tool_names = {
            "search_files_multi",
            "search_files",
            "read_files",
            "read_file",
            "get_file_outline",
            "report_findings",
        }
        tools = [t for t in RESPONSES_TOOL_DEFS if t.get("name") in tool_names]
        cache_key = f"ruf:{Path(self.root_path).name}:{self.config.model}:final"

        result = ai.execute(
            prompt,
            "Finalize the complete audit findings now.",
            model=self.config.model,
            reasoning_effort="high",
            verbosity="high",
            tools=tools,
            tool_choice="auto",
            prompt_cache_key=cache_key,
            prompt_cache_retention=self.config.prompt_cache_retention,
            max_turns=12,
            max_tool_calls=12,
        )
        _log_api_metrics(
            stage="final-global-validation",
            phase="final-validation",
            model=self.config.model,
            reasoning_effort="high",
            verbosity="high",
            result=result,
        )

        final = _parse_findings(
            result.get("findings", []),
            pass_num=5,
            phase_name="final-validation",
            root_path=self.root_path,
        )
        final = _dedupe_issues_strict(final)

        self.memory.issues = final
        self.memory.final_summary = (result.get("analysis_summary") or "").strip()

        console.print(
            f"  [red]Final confirmed findings: {len(final)} (from {len(candidates)} candidates)[/red]"
        )
        _display_issues(final, "Final Validated Findings")

    # ==================================================================
    # Step 6 — Build report
    # ==================================================================

    def _build_report(self) -> AuditReport:
        confirmed = self.memory.get_confirmed_issues()

        by_sev: dict[str, int] = {}
        for i in confirmed:
            by_sev[i.severity.value] = by_sev.get(i.severity.value, 0) + 1

        breakdown = ", ".join(f"{v} {k}" for k, v in sorted(by_sev.items()))

        summary = (
            self.memory.final_summary.strip()
            if getattr(self.memory, "final_summary", "").strip()
            else (
                f"Audit completed with {len(confirmed)} confirmed findings "
                f"across {len(self.memory.phases)} phases. "
                f"Breakdown: {breakdown}."
            )
        )

        return AuditReport(
            project_name=Path(self.root_path).name,
            target_path=self.target_path,
            root_path=self.root_path,
            phases=self.memory.phases,
            issues=confirmed,
            summary=summary,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )


# ======================================================================
# Helpers
# ======================================================================

_ANCHOR_FENCE_RE = re.compile(r"^\s*```")
_ANCHOR_LINENO_RE = re.compile(r"^\s*(?:L?\d+\s*[:|]\s*)")


def _clean_code_anchor(anchor: object) -> list[str]:
    if not isinstance(anchor, str):
        return []
    lines = []
    for ln in anchor.splitlines():
        if _ANCHOR_FENCE_RE.match(ln):
            continue
        ln = _ANCHOR_LINENO_RE.sub("", ln)
        lines.append(ln.rstrip())
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return lines[:5]


def _safe_read_lines(root_path: str | None, rel_path: str) -> list[str] | None:
    if not root_path:
        return None
    root = Path(root_path).resolve()
    try:
        target = (root / rel_path).resolve()
        target.relative_to(root)
    except Exception:
        return None
    if not target.is_file():
        return None
    try:
        text = target.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None
    return text.splitlines()


def _find_anchor_start(
    file_lines: list[str],
    anchor_lines: list[str],
    hint_start: int | None,
) -> int | None:
    if not file_lines or not anchor_lines:
        return None

    def norm(s: str) -> str:
        return _ANCHOR_LINENO_RE.sub("", s).rstrip()

    cand: list[int] = []
    n = len(anchor_lines)
    for i in range(0, len(file_lines) - n + 1):
        ok = True
        for j in range(n):
            if norm(file_lines[i + j]) != norm(anchor_lines[j]):
                ok = False
                break
        if ok:
            cand.append(i)

    # Fallback: ignore leading whitespace
    if not cand:
        for i in range(0, len(file_lines) - n + 1):
            ok = True
            for j in range(n):
                if norm(file_lines[i + j]).lstrip() != norm(anchor_lines[j]).lstrip():
                    ok = False
                    break
            if ok:
                cand.append(i)

    if not cand:
        return None
    if hint_start and hint_start > 0:
        return min(cand, key=lambda idx: abs((idx + 1) - hint_start))
    return cand[0]


def _resolve_line_range(
    *,
    root_path: str | None,
    file_path: str,
    hint_start: int | None,
    hint_end: int | None,
    code_anchor: object,
) -> tuple[int | None, int | None]:
    lines = _safe_read_lines(root_path, file_path)
    if not lines:
        return hint_start, hint_end

    total = len(lines)
    hs = hint_start if isinstance(hint_start, int) else None
    he = hint_end if isinstance(hint_end, int) else None
    if hs is not None:
        hs = max(1, min(hs, total))
    if he is not None:
        he = max(1, min(he, total))

    anchor_lines = _clean_code_anchor(code_anchor)
    if anchor_lines:
        idx = _find_anchor_start(lines, anchor_lines, hs)
        if idx is not None:
            start = idx + 1
            end = start + len(anchor_lines) - 1 if len(anchor_lines) > 1 else None
            return start, end

    return hs, he


def _parse_findings(
    raw: list[dict],
    pass_num: int,
    phase_name: str,
    *,
    root_path: str | None = None,
) -> list[Issue]:
    issues: list[Issue] = []
    for f in raw:
        file_path = str(f.get("file_path", "unknown") or "unknown").strip() or "unknown"

        ls = f.get("line_start")
        le = f.get("line_end")
        try:
            ls_i = int(ls) if ls is not None else None
        except Exception:
            ls_i = None
        try:
            le_i = int(le) if le is not None else None
        except Exception:
            le_i = None

        resolved_start, resolved_end = _resolve_line_range(
            root_path=root_path,
            file_path=file_path,
            hint_start=ls_i,
            hint_end=le_i,
            code_anchor=f.get("code_anchor"),
        )
        try:
            sev = Severity(f.get("severity", "informational"))
        except ValueError:
            sev = Severity.INFORMATIONAL
        issues.append(Issue(
            title=f.get("title", "Untitled"),
            severity=sev,
            category=f.get("category", "unknown"),
            file_path=file_path,
            line_start=resolved_start,
            line_end=resolved_end,
            description=f.get("description", ""),
            impact=f.get("impact", ""),
            recommendation=f.get("recommendation", ""),
            proof_of_concept=f.get("proof_of_concept"),
            found_in_pass=pass_num,
            phase=phase_name,
        ))
    return issues


def _dedupe_issues_strict(issues: list[Issue]) -> list[Issue]:
    """Strict dedupe to prevent repeated identical findings in the final report."""
    seen: set[tuple[str, int, int, str]] = set()
    out: list[Issue] = []
    for i in issues:
        key = (
            (i.file_path or "unknown").strip(),
            int(i.line_start or 0),
            int(i.line_end or 0),
            (i.title or "").strip().lower(),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(i)
    return out


SEV_COLORS = {
    "critical": "red",
    "high": "bright_red",
    "medium": "yellow",
    "low": "blue",
    "informational": "dim",
    "gas": "green",
}


def _display_issues(issues: list[Issue], title: str) -> None:
    if not issues:
        return
    tbl = Table(title=title)
    tbl.add_column("Severity", style="bold")
    tbl.add_column("Title")
    tbl.add_column("Location")
    tbl.add_column("Category", style="dim")

    for issue in sorted(issues, key=lambda i: Severity.rank(i.severity)):
        color = SEV_COLORS.get(issue.severity.value, "white")
        loc = issue.file_path
        if issue.line_start:
            loc += f":{issue.line_start}"
        tbl.add_row(
            f"[{color}]{issue.severity.value.upper()}[/{color}]",
            issue.title,
            loc,
            issue.category,
        )
    console.print(tbl)


def _section(title: str, color: str) -> None:
    rule = "═" * 60
    console.print(f"\n[bold {color}]{rule}[/bold {color}]")
    console.print(f"[bold {color}]{title}[/bold {color}]")
    console.print(f"[bold {color}]{rule}[/bold {color}]")


def _slug_key(text: str, max_len: int = 48) -> str:
    s = (text or "").strip().lower()
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    return (s or "phase")[:max_len]


def _log_api_metrics(
    *,
    stage: str,
    phase: str,
    model: str,
    reasoning_effort: str,
    verbosity: str,
    result: dict,
) -> None:
    usage = result.get("usage") if isinstance(result, dict) else None
    elapsed_ms = result.get("elapsed_ms") if isinstance(result, dict) else None
    if not isinstance(usage, dict):
        usage = {}
    cached = usage.get("cached_tokens", 0)
    inp = usage.get("input_tokens", 0)
    out = usage.get("output_tokens", 0)
    total = usage.get("total_tokens", 0)
    rtok = usage.get("reasoning_tokens", 0)
    ms = int(elapsed_ms) if isinstance(elapsed_ms, int) else None

    msg = (
        f"[dim]API {stage} | {phase} | model={model} effort={reasoning_effort} "
        f"verb={verbosity} | in={inp} cached={cached} out={out} "
        f"reason={rtok} total={total}"
        + (f" | {ms}ms" if ms is not None else "")
        + "[/dim]"
    )
    console.print(msg)


def _detect_project_root(target: Path) -> Path:
    """Best-effort project-root detection for single-file audits."""
    start = target if target.is_dir() else target.parent
    markers = (
        ".git",
        "foundry.toml",
        "hardhat.config.ts",
        "hardhat.config.js",
        "package.json",
        "truffle-config.js",
        "brownie-config.yaml",
        "Cargo.toml",
        "Move.toml",
        "Scarb.toml",
    )
    for cand in (start, *start.parents):
        for m in markers:
            if (cand / m).exists():
                return cand
    return start
