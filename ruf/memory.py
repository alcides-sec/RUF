"""Structured memory that carries context across audit executions."""

from __future__ import annotations

import json
from typing import Optional

from .models import Issue, IssueStatus, Phase


class AuditMemory:
    """Accumulates findings, observations, and phase summaries across the
    entire audit pipeline so each execution has access to everything that
    came before it."""

    def __init__(self) -> None:
        self.phases: list[Phase] = []
        self.issues: list[Issue] = []
        self.phase_summaries: dict[str, str] = {}
        self.observations: list[str] = []
        self.file_tree: str = ""
        self.final_summary: str = ""

    # ------------------------------------------------------------------
    # Mutators
    # ------------------------------------------------------------------

    def add_issues(self, issues: list[Issue]) -> None:
        self.issues.extend(issues)

    def add_phase_summary(self, phase_name: str, summary: str) -> None:
        self.phase_summaries[phase_name] = summary

    def add_observation(self, observation: str) -> None:
        self.observations.append(observation)

    def mark_false_positives(self, ids: set[str]) -> None:
        for issue in self.issues:
            if issue.id in ids:
                issue.status = IssueStatus.FALSE_POSITIVE

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_issues_for_phase(self, phase_name: str) -> list[Issue]:
        return [i for i in self.issues if i.phase == phase_name]

    def get_confirmed_issues(self) -> list[Issue]:
        return [i for i in self.issues if i.status == IssueStatus.CONFIRMED]

    # ------------------------------------------------------------------
    # Context serialisation — what gets injected into prompts
    # ------------------------------------------------------------------

    def get_context_summary(self, max_issues: int = 200) -> str:
        """Produce a compressed context string for carrying forward."""
        sections: list[str] = []

        if self.file_tree:
            sections.append(f"## Project Structure\n```\n{self.file_tree}\n```")

        if self.phases:
            rows = "\n".join(
                f"- **{p.name}**: {p.description}  \n"
                f"  Files: {', '.join(p.files)}  \n"
                f"  Deps: {', '.join(p.dependencies) or 'none'}"
                for p in self.phases
            )
            sections.append(f"## Audit Phases\n{rows}")

        if self.phase_summaries:
            rows = "\n".join(
                f"### {name}\n{summary}"
                for name, summary in self.phase_summaries.items()
            )
            sections.append(f"## Completed Phase Summaries\n{rows}")

        confirmed = self.get_confirmed_issues()
        if confirmed:
            subset = confirmed[:max_issues]
            rows = "\n".join(
                f"- [{i.severity.value.upper()}] **{i.title}** "
                f"(`{i.file_path}`:{i.line_start or '?'}) — "
                f"{i.description[:300]}"
                for i in subset
            )
            extra = ""
            if len(confirmed) > max_issues:
                extra = f"\n\n_(showing {max_issues} of {len(confirmed)} issues)_"
            sections.append(
                f"## Confirmed Issues ({len(confirmed)} total)\n{rows}{extra}"
            )

        if self.observations:
            latest = self.observations[-30:]
            rows = "\n".join(f"- {o}" for o in latest)
            sections.append(f"## Key Observations\n{rows}")

        return "\n\n".join(sections)

    def get_issues_json(self, confirmed_only: bool = True) -> str:
        pool = self.get_confirmed_issues() if confirmed_only else self.issues
        return json.dumps([i.to_dict() for i in pool], indent=2)

    def get_all_issues_json(self) -> str:
        return json.dumps([i.to_dict() for i in self.issues], indent=2)
