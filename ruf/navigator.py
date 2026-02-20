"""File-system navigator that gives the AI Cursor-like read/search abilities."""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from typing import Any

from .config import Config


def _glob_match(rel_path: str, pattern: str) -> bool:
    """Match a relative path against a glob pattern with proper ** support.

    ``**`` is treated as "zero or more directories", so
    ``src/**/*.rs`` matches both ``src/types.rs`` and ``src/sub/types.rs``.
    """
    if fnmatch.fnmatch(rel_path, pattern):
        return True
    if "**" in pattern:
        # Collapse **/ to nothing → matches zero intermediate dirs
        collapsed = pattern.replace("**/", "")
        if fnmatch.fnmatch(rel_path, collapsed):
            return True
        # Also try replacing /**/ with / for mid-path **
        collapsed2 = pattern.replace("/**/", "/")
        if fnmatch.fnmatch(rel_path, collapsed2):
            return True
    return False


# ---------------------------------------------------------------------------
# Tool definitions exposed to the OpenAI function-calling API
# ---------------------------------------------------------------------------

TOOL_DEFS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "list_directory",
            "description": "List the contents of a directory in the project.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Relative path to the directory (use '.' for root)",
                    },
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": (
                "Read a file's contents with line numbers. "
                "Optionally pass start_line / end_line for a slice."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Relative path to the file",
                    },
                    "start_line": {
                        "type": "integer",
                        "description": "First line to read (1-indexed, optional)",
                    },
                    "end_line": {
                        "type": "integer",
                        "description": "Last line to read (inclusive, optional)",
                    },
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_files",
            "description": "Search for a regex pattern across project files.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Regex pattern to search for",
                    },
                    "file_glob": {
                        "type": "string",
                        "description": "Optional glob to filter files (e.g. '*.sol')",
                    },
                },
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_files_multi",
            "description": "Run multiple regex searches across project files (batched).",
            "parameters": {
                "type": "object",
                "properties": {
                    "queries": {
                        "type": "array",
                        "description": "List of searches to run",
                        "items": {
                            "type": "object",
                            "properties": {
                                "pattern": {"type": "string"},
                                "file_glob": {
                                    "type": "string",
                                    "description": "Optional glob filter, e.g. '**/*.rs'",
                                },
                            },
                            "required": ["pattern"],
                        },
                    },
                },
                "required": ["queries"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_file_outline",
            "description": (
                "Return a high-level outline of a source file "
                "(contract/function/event/modifier signatures) without the full body."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Relative path to the file",
                    },
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_files",
            "description": "Read multiple files with line numbers (batched).",
            "parameters": {
                "type": "object",
                "properties": {
                    "files": {
                        "type": "array",
                        "description": "Files to read",
                        "items": {
                            "type": "object",
                            "properties": {
                                "path": {"type": "string"},
                                "start_line": {"type": "integer"},
                                "end_line": {"type": "integer"},
                            },
                            "required": ["path"],
                        },
                    },
                },
                "required": ["files"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "report_findings",
            "description": (
                "Submit security findings from the current analysis. "
                "Call this when your analysis is complete."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "findings": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "title": {"type": "string"},
                                "severity": {
                                    "type": "string",
                                    "enum": [
                                        "critical", "high", "medium",
                                        "low", "informational", "gas",
                                    ],
                                },
                                "category": {"type": "string"},
                                "file_path": {"type": "string"},
                                "line_start": {"type": "integer"},
                                "line_end": {"type": "integer"},
                                "code_anchor": {
                                    "type": "string",
                                    "description": (
                                        "Exact snippet (2-5 consecutive lines) copied verbatim from the file near the issue, "
                                        "including at least one likely-unique line. Used to deterministically locate line numbers."
                                    ),
                                },
                                "description": {"type": "string"},
                                "impact": {"type": "string"},
                                "recommendation": {"type": "string"},
                                "proof_of_concept": {"type": "string"},
                            },
                            "required": [
                                "title", "severity", "category",
                                "file_path", "description", "impact",
                                "recommendation", "code_anchor",
                            ],
                        },
                    },
                    "analysis_summary": {
                        "type": "string",
                        "description": "Summary of the analysis performed",
                    },
                },
                "required": ["findings", "analysis_summary"],
            },
        },
    },
]

# Tool definitions for the Responses API (FunctionToolParam shape)
RESPONSES_TOOL_DEFS: list[dict] = [
    {
        "type": "function",
        "name": t["function"]["name"],
        "description": t["function"].get("description", ""),
        "parameters": t["function"].get("parameters"),
        "strict": False,
    }
    for t in TOOL_DEFS
]


class Navigator:
    """Provides filesystem tools scoped to a project root."""

    def __init__(self, root_path: str, config: Config) -> None:
        self.root = Path(root_path).resolve()
        self.config = config

    def _is_ignored(self, rel: Path) -> bool:
        for part in rel.parts:
            for pattern in self.config.ignored_dirs:
                if "*" in pattern:
                    if fnmatch.fnmatch(part, pattern):
                        return True
                elif part == pattern:
                    return True
        return False

    def _resolve_under_root(self, relative_path: str) -> Path | None:
        target = (self.root / relative_path).resolve()
        try:
            target.relative_to(self.root)
        except ValueError:
            return None
        return target

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def get_file_tree(self, max_depth: int = 6) -> str:
        lines: list[str] = [self.root.name + "/"]
        self._build_tree(self.root, lines, "", depth=0, max_depth=max_depth)
        return "\n".join(lines)

    def get_all_files(self) -> list[Path]:
        files: list[Path] = []
        for ext in self.config.supported_extensions:
            for fp in self.root.rglob(f"*{ext}"):
                rel = fp.relative_to(self.root)
                if self._is_ignored(rel):
                    continue
                files.append(fp)
        return sorted(files)

    def get_all_file_paths(self) -> list[str]:
        return [str(f.relative_to(self.root)) for f in self.get_all_files()]

    def get_line_counts(self, paths: list[str]) -> dict[str, int]:
        """Return ``{relative_path: total_line_count}`` for each path."""
        counts: dict[str, int] = {}
        for p in paths:
            target = self._resolve_under_root(p)
            if target is None or not target.is_file():
                continue
            try:
                text = target.read_text(encoding="utf-8", errors="replace")
                counts[p] = len(text.splitlines())
            except Exception:
                continue
        return counts

    # ------------------------------------------------------------------
    # Tool implementations
    # ------------------------------------------------------------------

    def list_directory(self, path: str = ".") -> dict:
        target = self._resolve_under_root(path)
        if target is None:
            return {"error": "Access denied: path outside project root"}
        if not target.is_dir():
            return {"error": f"Not a directory: {path}"}

        entries: list[dict] = []
        for entry in sorted(target.iterdir()):
            rel = entry.relative_to(self.root)
            if self._is_ignored(rel):
                continue
            entries.append({
                "name": entry.name,
                "type": "directory" if entry.is_dir() else "file",
                "size": entry.stat().st_size if entry.is_file() else None,
                "path": str(rel),
            })
        return {"path": path, "entries": entries}

    def read_file(
        self,
        path: str,
        start_line: int | None = None,
        end_line: int | None = None,
    ) -> dict:
        target = self._resolve_under_root(path)
        if target is None:
            return {"error": "Access denied: path outside project root"}
        if not target.is_file():
            return {"error": f"Not a file: {path}"}

        try:
            content = target.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            return {"error": f"Failed to read {path}: {exc}"}

        all_lines = content.splitlines()
        total = len(all_lines)

        if start_line is not None or end_line is not None:
            s = max((start_line or 1) - 1, 0)
            e = min(end_line or total, total)
            lines = all_lines[s:e]
            offset = s
        else:
            lines = all_lines
            offset = 0

        numbered = [f"{i + offset + 1:6}|{ln}" for i, ln in enumerate(lines)]
        return {
            "path": path,
            "total_lines": total,
            "showing": f"{offset + 1}-{offset + len(lines)}",
            "content": "\n".join(numbered),
        }

    def read_file_plain(
        self,
        path: str,
        start_line: int | None = None,
        end_line: int | None = None,
    ) -> dict:
        """Read a file without adding per-line number prefixes.

        This is primarily used for prompt preloading to reduce token usage.
        """
        target = self._resolve_under_root(path)
        if target is None:
            return {"error": "Access denied: path outside project root"}
        if not target.is_file():
            return {"error": f"Not a file: {path}"}

        try:
            content = target.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            return {"error": f"Failed to read {path}: {exc}"}

        all_lines = content.splitlines()
        total = len(all_lines)

        if start_line is not None or end_line is not None:
            s = max((start_line or 1) - 1, 0)
            e = min(end_line or total, total)
            lines = all_lines[s:e]
            offset = s
        else:
            lines = all_lines
            offset = 0

        return {
            "path": path,
            "total_lines": total,
            "showing": f"{offset + 1}-{offset + len(lines)}",
            "content": "\n".join(lines),
        }

    def read_files(self, files: list[dict]) -> dict:
        """Batch version of read_file."""
        results: list[dict] = []
        for f in files:
            path = f.get("path")
            if not path:
                continue
            results.append(self.read_file(path, f.get("start_line"), f.get("end_line")))
        return {"results": results}

    def search_files(
        self,
        pattern: str,
        file_glob: str | None = None,
    ) -> dict:
        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            return {"error": f"Invalid regex: {exc}"}

        results: list[dict] = []
        for fp in self.get_all_files():
            if file_glob:
                rel = fp.relative_to(self.root).as_posix()
                if not _glob_match(rel, file_glob):
                    continue
            try:
                text = fp.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            for i, line in enumerate(text.splitlines(), 1):
                if regex.search(line):
                    results.append({
                        "file": str(fp.relative_to(self.root)),
                        "line": i,
                        "content": line.strip(),
                    })
                    if len(results) >= 200:
                        return {"pattern": pattern, "results": results, "truncated": True}

        return {"pattern": pattern, "results": results, "truncated": False}

    def search_files_multi(self, queries: list[dict]) -> dict:
        """Batch version of search_files."""
        results: list[dict] = []
        for q in queries:
            pattern = q.get("pattern")
            if not pattern:
                continue
            results.append(self.search_files(pattern, q.get("file_glob")))
        return {"results": results}

    def get_file_outline(self, path: str) -> dict:
        """Extract a structural outline (signatures only) from a source file."""
        target = self._resolve_under_root(path)
        if target is None:
            return {"error": "Access denied: path outside project root"}
        if not target.is_file():
            return {"error": f"Not a file: {path}"}

        try:
            text = target.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            return {"error": str(exc)}

        sig_patterns = [
            re.compile(r"^\s*(contract|library|interface|abstract\s+contract)\s+\w+", re.M),
            re.compile(r"^\s*function\s+\w+", re.M),
            re.compile(r"^\s*modifier\s+\w+", re.M),
            re.compile(r"^\s*event\s+\w+", re.M),
            re.compile(r"^\s*error\s+\w+", re.M),
            re.compile(r"^\s*struct\s+\w+", re.M),
            re.compile(r"^\s*enum\s+\w+", re.M),
            re.compile(r"^\s*mapping\s*\(", re.M),
            re.compile(r"^\s*(pub\s+)?(fn|struct|enum|trait|impl|mod)\s+\w+", re.M),
            re.compile(r"^\s*(public\s+)?(entry\s+)?fun\s+\w+", re.M),
        ]

        lines = text.splitlines()
        outline: list[str] = []
        for idx, line in enumerate(lines, 1):
            for pat in sig_patterns:
                if pat.match(line):
                    outline.append(f"{idx:6}|{line.rstrip()}")
                    break

        return {"path": path, "total_lines": len(lines), "outline": "\n".join(outline)}

    # ------------------------------------------------------------------
    # Dispatcher used by AIClient
    # ------------------------------------------------------------------

    def execute_tool(self, name: str, arguments: dict[str, Any]) -> dict:
        dispatch = {
            "list_directory": lambda a: self.list_directory(a.get("path", ".")),
            "read_file": lambda a: self.read_file(
                a["path"], a.get("start_line"), a.get("end_line"),
            ),
            "read_files": lambda a: self.read_files(a.get("files", [])),
            "search_files": lambda a: self.search_files(
                a["pattern"], a.get("file_glob"),
            ),
            "search_files_multi": lambda a: self.search_files_multi(a.get("queries", [])),
            "get_file_outline": lambda a: self.get_file_outline(a["path"]),
            "report_findings": lambda a: a,  # pipeline handles this
        }
        handler = dispatch.get(name)
        if handler is None:
            return {"error": f"Unknown tool: {name}"}
        return handler(arguments)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _build_tree(
        self,
        path: Path,
        lines: list[str],
        prefix: str,
        depth: int,
        max_depth: int,
    ) -> None:
        if depth >= max_depth:
            return
        entries = sorted(path.iterdir(), key=lambda e: (not e.is_dir(), e.name))
        entries = [
            e for e in entries
            if not self._is_ignored(e.relative_to(self.root))
        ]
        for i, entry in enumerate(entries):
            is_last = i == len(entries) - 1
            connector = "\u2514\u2500\u2500 " if is_last else "\u251c\u2500\u2500 "
            lines.append(f"{prefix}{connector}{entry.name}")
            if entry.is_dir():
                ext = "    " if is_last else "\u2502   "
                self._build_tree(entry, lines, prefix + ext, depth + 1, max_depth)
