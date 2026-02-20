from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    GAS = "gas"

    @classmethod
    def rank(cls, sev: Severity) -> int:
        return list(cls).index(sev)


class IssueStatus(str, Enum):
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    DISPUTED = "disputed"


@dataclass
class Issue:
    title: str
    severity: Severity
    category: str
    file_path: str
    description: str
    impact: str
    recommendation: str
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    status: IssueStatus = IssueStatus.CONFIRMED
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    proof_of_concept: Optional[str] = None
    found_in_pass: int = 1
    phase: str = ""
    severity_notes: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "status": self.status.value,
            "category": self.category,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "description": self.description,
            "impact": self.impact,
            "recommendation": self.recommendation,
            "proof_of_concept": self.proof_of_concept,
            "found_in_pass": self.found_in_pass,
            "phase": self.phase,
            "severity_notes": self.severity_notes,
        }


@dataclass
class Phase:
    name: str
    description: str
    reasoning: str
    files: list[str]
    dependencies: list[str] = field(default_factory=list)


@dataclass
class AuditReport:
    project_name: str
    target_path: str
    root_path: str
    phases: list[Phase]
    issues: list[Issue]
    summary: str = ""
    methodology: str = ""
    timestamp: str = ""

    def to_dict(self) -> dict:
        return {
            "project_name": self.project_name,
            "target_path": self.target_path,
            "root_path": self.root_path,
            "phases": [
                {
                    "name": p.name,
                    "description": p.description,
                    "reasoning": p.reasoning,
                    "files": p.files,
                    "dependencies": p.dependencies,
                }
                for p in self.phases
            ],
            "issues": [i.to_dict() for i in self.issues],
            "summary": self.summary,
            "methodology": self.methodology,
            "timestamp": self.timestamp,
        }
