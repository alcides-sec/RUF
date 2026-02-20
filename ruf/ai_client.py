"""OpenAI API client with tool-calling loop, coverage enforcement, and
context-window management."""

from __future__ import annotations

import json
import re
import time
from typing import Any

from openai import OpenAI, APIError, NotFoundError, RateLimitError
from rich.console import Console

from .config import Config
from .navigator import Navigator, TOOL_DEFS

console = Console()

MAX_TOOL_ITERATIONS = 80
RETRY_ATTEMPTS = 10
RETRY_BASE_DELAY = 5.0
RETRY_MAX_DELAY = 120.0


# ======================================================================
# Read-coverage tracker
# ======================================================================

class _ReadTracker:
    """Ensures every required file has been fully read before findings
    can be submitted.  Tracks line-ranges per file and merges them to
    determine coverage."""

    def __init__(self, required: dict[str, int]) -> None:
        self._required = required          # {path: total_lines}
        self._ranges: dict[str, list[tuple[int, int]]] = {}

    def record(
        self,
        path: str,
        start: int | None,
        end: int | None,
        total_lines: int,
    ) -> None:
        s = start or 1
        e = end or total_lines
        self._ranges.setdefault(path, []).append((s, e))

    def get_unread_files(self) -> list[str]:
        unread: list[str] = []
        for path, total in self._required.items():
            if path not in self._ranges:
                unread.append(path)
            else:
                covered = self._covered_lines(path)
                # 95 % threshold avoids off-by-one false alarms on trailing newlines
                if covered < total * 0.95:
                    unread.append(f"{path} ({covered}/{total} lines read)")
        return unread

    @property
    def all_covered(self) -> bool:
        return len(self.get_unread_files()) == 0

    def _covered_lines(self, path: str) -> int:
        ranges = sorted(self._ranges.get(path, []))
        if not ranges:
            return 0
        merged: list[list[int]] = [list(ranges[0])]
        for s, e in ranges[1:]:
            if s <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], e)
            else:
                merged.append([s, e])
        return sum(e - s + 1 for s, e in merged)


# ======================================================================
# AI Client
# ======================================================================

class AIClient:
    def __init__(self, config: Config, navigator: Navigator) -> None:
        self.config = config
        self.navigator = navigator
        self.client = OpenAI(api_key=config.api_key, base_url=config.base_url)

    # ------------------------------------------------------------------
    # Full agentic execution with tool calling
    # ------------------------------------------------------------------

    def execute(
        self,
        system_prompt: str,
        user_message: str,
        tools: list[dict] | None = None,
        required_reads: dict[str, int] | None = None,
        pre_read_paths: set[str] | None = None,
        force_report_first_turn: bool = False,
    ) -> dict[str, Any]:
        """Run an agentic loop.  The model calls tools (read_file, search,
        etc.) until it stops or calls ``report_findings``.

        *required_reads* — ``{filepath: line_count}``.  When provided the
        model **must** read every listed file before ``report_findings``
        is accepted.  Rejected calls are buffered and auto-included once
        coverage is satisfied.

        *pre_read_paths* — files already embedded in the user message.
        These are pre-marked as fully read in the tracker so the model
        doesn't waste tool calls re-reading them.

        Returns ``{"response", "findings", "analysis_summary", "messages"}``.
        """
        if tools is None:
            tools = TOOL_DEFS

        messages: list[dict] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ]

        findings: list[dict] = []
        buffered_findings: list[dict] = []
        analysis_summary = ""
        tracker = _ReadTracker(required_reads) if required_reads else None
        coverage_notified = False

        # Pre-mark files that were embedded in the prompt as fully read.
        if tracker and pre_read_paths and required_reads:
            for path in pre_read_paths:
                total = required_reads.get(path, 0)
                if total > 0:
                    tracker.record(path, None, None, total)

        # If content was pre-loaded, delay the "finalize now" nudge so the model
        # has time to actually analyze instead of immediately calling report_findings.
        min_finalize_nudge_step = 8 if pre_read_paths else 0

        max_iters = getattr(self.config, "max_tool_iterations", MAX_TOOL_ITERATIONS)
        report_only_tools = [
            t for t in tools
            if t.get("type") == "function"
            and t.get("function", {}).get("name") == "report_findings"
        ]

        for step in range(max_iters):
            # --- context-window management (only at 85% to avoid over-pruning) ---
            if self._estimate_tokens(messages) > self.config.max_context_tokens * 0.85:
                self._prune_messages(messages, keep_recent=25)

            # If coverage is complete, nudge the model to finalize.
            if tracker and tracker.all_covered and not coverage_notified and step >= min_finalize_nudge_step:
                messages.append({
                    "role": "system",
                    "content": (
                        "All required files for this phase have been fully read. "
                        "Stop calling tools unless needed to confirm a specific line. "
                        "Call report_findings now with your findings (include low/info/gas)."
                    ),
                })
                coverage_notified = True

            # Force report_findings when requested (one-shot mode), or when we're
            # about to run out of tool iterations after coverage is complete.
            can_force = (tracker is None) or tracker.all_covered
            force_report = bool(
                report_only_tools
                and can_force
                and (
                    force_report_first_turn
                    or (tracker and tracker.all_covered and (max_iters - step) <= 2)
                )
            )
            active_tools = report_only_tools if force_report else tools
            tool_choice = (
                {"type": "function", "function": {"name": "report_findings"}}
                if force_report
                else None
            )

            response = self._chat(messages, tools=active_tools, tool_choice=tool_choice)
            choice = response.choices[0]
            msg = choice.message

            messages.append(_serialize_message(msg))

            if not msg.tool_calls:
                # If the model stopped without re-calling report_findings, flush buffered findings.
                if buffered_findings and (tracker is None or tracker.all_covered):
                    findings.extend(buffered_findings)
                    buffered_findings.clear()
                return {
                    "response": msg.content or "",
                    "findings": findings,
                    "analysis_summary": analysis_summary,
                    "messages": messages,
                }

            for tc in msg.tool_calls:
                name = tc.function.name
                try:
                    args = json.loads(tc.function.arguments)
                except json.JSONDecodeError:
                    args = {}

                self._log_tool_call(name, args)

                if name == "report_findings":
                    result = self._handle_report_findings(
                        args, tracker, findings, buffered_findings,
                    )
                    if "error" not in result:
                        analysis_summary = args.get("analysis_summary", analysis_summary)
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": json.dumps(result, default=str),
                    })
                    # Successful report_findings marks the end of the pass.
                    if "error" not in result:
                        return {
                            "response": "",
                            "findings": findings,
                            "analysis_summary": analysis_summary,
                            "messages": messages,
                        }
                    continue
                else:
                    result = self.navigator.execute_tool(name, args)
                    if tracker:
                        if name == "read_file" and "error" not in result:
                            tracker.record(
                                args["path"],
                                args.get("start_line"),
                                args.get("end_line"),
                                result.get("total_lines", 0),
                            )
                        elif name == "read_files":
                            returned = result.get("results", []) if isinstance(result, dict) else []
                            by_path = {
                                r.get("path"): r for r in returned
                                if isinstance(r, dict) and r.get("path")
                            }
                            for req in args.get("files", []) or []:
                                if not isinstance(req, dict):
                                    continue
                                path = req.get("path")
                                if not path:
                                    continue
                                r = by_path.get(path, {})
                                if isinstance(r, dict) and "error" not in r:
                                    tracker.record(
                                        path,
                                        req.get("start_line"),
                                        req.get("end_line"),
                                        r.get("total_lines", 0),
                                    )

                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": json.dumps(result, default=str),
                })

        console.print("[yellow]  (max tool iterations reached)[/yellow]")
        return {
            "response": "",
            "findings": findings,
            "analysis_summary": analysis_summary,
            "messages": messages,
        }

    # ------------------------------------------------------------------
    # Simple completions (no tools)
    # ------------------------------------------------------------------

    def execute_simple(self, system_prompt: str, user_message: str) -> str:
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ]
        resp = self._chat(messages, tools=None)
        return resp.choices[0].message.content or ""

    def execute_json(self, system_prompt: str, user_message: str) -> dict:
        """Call the model and parse JSON from its response."""
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ]
        resp = self._chat(messages, tools=None, json_mode=True)
        text = resp.choices[0].message.content or "{}"
        return _extract_json(text)

    # ------------------------------------------------------------------
    # Coverage enforcement
    # ------------------------------------------------------------------

    @staticmethod
    def _handle_report_findings(
        args: dict,
        tracker: _ReadTracker | None,
        findings: list[dict],
        buffered: list[dict],
    ) -> dict:
        incoming = args.get("findings", [])

        if tracker and not tracker.all_covered:
            # Buffer the findings so they aren't lost
            buffered.extend(incoming)
            unread = tracker.get_unread_files()
            console.print(
                f"    [yellow]\u26a0 Rejecting findings \u2014 "
                f"{len(unread)} file(s) not yet fully read[/yellow]"
            )
            return {
                "error": (
                    "Cannot submit findings yet \u2014 you must read ALL "
                    "required files first."
                ),
                "unread_files": unread,
                "instruction": (
                    "Use read_file to read each file listed above, "
                    "then call report_findings again."
                ),
                "note": (
                    f"Your {len(incoming)} finding(s) have been saved and "
                    "will be included automatically once coverage is met."
                ),
            }

        # Coverage satisfied (or not enforced): accept everything
        all_new = buffered + incoming
        findings.extend(all_new)
        buffered.clear()
        return {"status": "findings recorded", "count": len(all_new)}

    # ------------------------------------------------------------------
    # Context-window management
    # ------------------------------------------------------------------

    @staticmethod
    def _estimate_tokens(messages: list[dict]) -> int:
        """Rough token estimate (~4 chars per token)."""
        return sum(len(json.dumps(m, default=str)) for m in messages) // 4

    @staticmethod
    def _prune_messages(messages: list[dict], keep_recent: int = 25) -> None:
        """Replace old, large tool results with compact summaries.

        Strategy (in priority order):
        1. Prune search_files results first (large, least valuable to keep).
        2. Prune older duplicate file reads (keep only the latest read per path).
        3. Generic truncation for anything else over 1 KB.

        The first two user/system messages and the *keep_recent* most
        recent messages are never touched."""
        cutoff = max(len(messages) - keep_recent, 0)
        pruned_count = 0

        # First pass: find the latest read_file result index for each path
        # so we can protect it from pruning.
        latest_read: dict[str, int] = {}
        for i, msg in enumerate(messages):
            if msg.get("role") != "tool":
                continue
            try:
                data = json.loads(msg.get("content", ""))
                if "path" in data and "content" in data:
                    latest_read[data["path"]] = i
            except (json.JSONDecodeError, TypeError):
                pass

        protected_indices = set(latest_read.values())

        for i in range(2, cutoff):  # skip system + user messages
            msg = messages[i]
            if msg.get("role") != "tool":
                continue
            content = msg.get("content", "")
            if len(content) <= 500:
                continue

            try:
                data = json.loads(content)

                # Search results: always safe to prune
                if "results" in data and "pattern" in data:
                    count = len(data.get("results", []))
                    messages[i]["content"] = json.dumps({
                        "pattern": data["pattern"],
                        "note": f"Search returned {count} result(s). Pruned to save context.",
                        "truncated": True,
                    })
                    pruned_count += 1
                    continue

                # File reads: only prune if a newer read of the same file exists
                if "path" in data and "content" in data:
                    if i not in protected_indices:
                        messages[i]["content"] = json.dumps({
                            "path": data["path"],
                            "total_lines": data.get("total_lines", "?"),
                            "note": "Older read; a newer read of this file exists. Pruned.",
                        })
                        pruned_count += 1
                    continue
            except (json.JSONDecodeError, TypeError):
                pass

            # Generic large content
            if len(content) > 1000:
                messages[i]["content"] = (
                    content[:500]
                    + "\n... [truncated to manage context window]"
                )
                pruned_count += 1

        if pruned_count:
            console.print(
                f"    [dim]\u2702 Pruned {pruned_count} old message(s) "
                f"to reclaim context space[/dim]"
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _chat(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
        json_mode: bool = False,
        tool_choice: dict | None = None,
    ):
        kwargs: dict[str, Any] = {
            "model": self.config.model,
            "messages": messages,
        }

        tier = getattr(self.config, "service_tier", "")
        if tier:
            kwargs["service_tier"] = tier

        # GPT-5.x: pass reasoning_effort + verbosity.
        # temperature is only supported when reasoning_effort == "none".
        eff = self.config.reasoning_effort
        if str(self.config.model).startswith("gpt-5"):
            kwargs["reasoning_effort"] = eff
            kwargs["verbosity"] = self.config.verbosity
            if eff == "none":
                kwargs["temperature"] = self.config.temperature
        else:
            kwargs["temperature"] = self.config.temperature

        if tools:
            kwargs["tools"] = tools
        if tool_choice is not None:
            kwargs["tool_choice"] = tool_choice
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}

        for attempt in range(1, RETRY_ATTEMPTS + 1):
            try:
                return self.client.chat.completions.create(**kwargs)
            except NotFoundError:
                raise RuntimeError(
                    f"Model '{self.config.model}' not found or you don't have access. "
                    "Override with --model or RUF_MODEL. "
                    "See: https://developers.openai.com/api/docs/guides/latest-model"
                )
            except RateLimitError:
                wait = min(RETRY_BASE_DELAY * (2 ** (attempt - 1)), RETRY_MAX_DELAY)
                console.print(
                    f"[yellow]  Rate-limited \u2014 waiting {wait:.0f}s "
                    f"(attempt {attempt}/{RETRY_ATTEMPTS})[/yellow]"
                )
                time.sleep(wait)
            except APIError as exc:
                if attempt == RETRY_ATTEMPTS:
                    raise
                wait = min(RETRY_BASE_DELAY * (2 ** (attempt - 1)), RETRY_MAX_DELAY)
                console.print(
                    f"[yellow]  API error ({exc}) \u2014 waiting {wait:.0f}s "
                    f"(attempt {attempt}/{RETRY_ATTEMPTS})[/yellow]"
                )
                time.sleep(wait)
        raise RuntimeError("Exhausted retries after 10 attempts")

    @staticmethod
    def _log_tool_call(name: str, args: dict) -> None:
        parts = ", ".join(f"{k}={v!r}" for k, v in args.items() if k != "findings")
        if name == "report_findings":
            count = len(args.get("findings", []))
            console.print(f"  [dim]\u2192 report_findings({count} issues)[/dim]")
        else:
            console.print(f"  [dim]\u2192 {name}({parts})[/dim]")


# ------------------------------------------------------------------
# Utilities
# ------------------------------------------------------------------

def _serialize_message(msg) -> dict:
    """Convert an OpenAI message object to a plain dict for the messages list."""
    d: dict[str, Any] = {"role": msg.role}
    if msg.content:
        d["content"] = msg.content
    if msg.tool_calls:
        d["tool_calls"] = [
            {
                "id": tc.id,
                "type": "function",
                "function": {
                    "name": tc.function.name,
                    "arguments": tc.function.arguments,
                },
            }
            for tc in msg.tool_calls
        ]
    return d


def _extract_json(text: str) -> dict:
    """Best-effort JSON extraction from model output."""
    text = text.strip()
    if text.startswith("{"):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

    match = re.search(r"```(?:json)?\s*\n(.*?)```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    brace = text.find("{")
    if brace != -1:
        candidate = text[brace:]
        depth = 0
        for i, ch in enumerate(candidate):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(candidate[: i + 1])
                    except json.JSONDecodeError:
                        break

    return {}
