"""Responses API client with per-phase session support.

This uses the OpenAI Responses API (vs Chat Completions) so we can keep a
continuous session via previous_response_id and avoid re-sending large inputs.
"""

from __future__ import annotations

import json
import time
from typing import Any

from openai import APIError, NotFoundError, OpenAI, RateLimitError
from rich.console import Console

from .config import Config
from .navigator import Navigator, RESPONSES_TOOL_DEFS

console = Console()

RETRY_ATTEMPTS = 10
RETRY_BASE_DELAY = 5.0
RETRY_MAX_DELAY = 120.0


def _response_text(resp) -> str:
    parts: list[str] = []
    for item in getattr(resp, "output", []) or []:
        if getattr(item, "type", None) != "message":
            continue
        for c in getattr(item, "content", []) or []:
            if getattr(c, "type", None) == "output_text":
                parts.append(getattr(c, "text", "") or "")
    return "\n".join(p for p in parts if p)


def _usage_to_dict(usage) -> dict[str, int]:
    if not usage:
        return {}
    cached = 0
    reasoning = 0
    try:
        cached = int(getattr(getattr(usage, "input_tokens_details", None), "cached_tokens", 0) or 0)
    except Exception:
        cached = 0
    try:
        reasoning = int(getattr(getattr(usage, "output_tokens_details", None), "reasoning_tokens", 0) or 0)
    except Exception:
        reasoning = 0
    return {
        "input_tokens": int(getattr(usage, "input_tokens", 0) or 0),
        "output_tokens": int(getattr(usage, "output_tokens", 0) or 0),
        "total_tokens": int(getattr(usage, "total_tokens", 0) or 0),
        "cached_tokens": cached,
        "reasoning_tokens": reasoning,
    }


def _log_tool_call(name: str, args: dict) -> None:
    if name == "report_findings":
        count = 0
        try:
            count = len(args.get("findings", []) or [])
        except Exception:
            count = 0
        console.print(f"  [dim]→ report_findings({count} issues)[/dim]")
        return
    if name == "read_file":
        path = args.get("path")
        s = args.get("start_line")
        e = args.get("end_line")
        parts = [f"path={path!r}"]
        if s is not None:
            parts.append(f"start_line={s!r}")
        if e is not None:
            parts.append(f"end_line={e!r}")
        console.print(f"  [dim]→ read_file({', '.join(parts)})[/dim]")
        return
    if name == "read_files":
        files = args.get("files")
        n = len(files) if isinstance(files, list) else 0
        console.print(f"  [dim]→ read_files({n} files)[/dim]")
        return
    if name == "search_files_multi":
        queries = args.get("queries")
        n = len(queries) if isinstance(queries, list) else 0
        console.print(f"  [dim]→ search_files_multi({n} queries)[/dim]")
        return
    if name == "search_files":
        pat = args.get("pattern")
        glob = args.get("file_glob")
        parts = [f"pattern={pat!r}"]
        if glob:
            parts.append(f"file_glob={glob!r}")
        console.print(f"  [dim]→ search_files({', '.join(parts)})[/dim]")
        return
    if name == "get_file_outline":
        console.print(f"  [dim]→ get_file_outline(path={args.get('path')!r})[/dim]")
        return
    if name == "list_directory":
        console.print(f"  [dim]→ list_directory(path={args.get('path')!r})[/dim]")
        return

    parts = ", ".join(
        f"{k}={v!r}"
        for k, v in args.items()
        if k not in {"findings", "content", "files", "queries"}
    )
    console.print(f"  [dim]→ {name}({parts})[/dim]")


class ResponsesAIClient:
    """Thin wrapper over OpenAI Responses API with retries and tool parsing."""

    def __init__(self, config: Config, navigator: Navigator) -> None:
        self.config = config
        self.navigator = navigator
        self.client = OpenAI(
            api_key=config.api_key or None,
            base_url=config.base_url,
        )

    def execute_navigation(
        self,
        instructions: str,
        user_input: str | list[dict[str, Any]],
        *,
        previous_response_id: str | None = None,
        tools: list[dict] | None = None,
        tool_choice: Any = "auto",
        json_mode: bool = False,
        prompt_cache_key: str | None = None,
        prompt_cache_retention: str | None = None,
        max_tool_calls: int | None = None,
    ) -> dict[str, Any]:
        """Run a navigation/tooling step on the faster navigation model."""
        return self.execute(
            instructions,
            user_input,
            model=self.config.navigation_model,
            previous_response_id=previous_response_id,
            tools=tools,
            tool_choice=tool_choice,
            json_mode=json_mode,
            prompt_cache_key=prompt_cache_key,
            prompt_cache_retention=prompt_cache_retention,
            reasoning_effort=self.config.navigation_reasoning_effort,
            verbosity=self.config.navigation_verbosity,
            max_tool_calls=max_tool_calls,
        )

    def execute(
        self,
        instructions: str,
        user_input: str | list[dict[str, Any]],
        *,
        model: str | None = None,
        previous_response_id: str | None = None,
        tools: list[dict] | None = None,
        tool_choice: Any = "auto",
        json_mode: bool = False,
        prompt_cache_key: str | None = None,
        prompt_cache_retention: str | None = None,
        reasoning_effort: str | None = None,
        verbosity: str | None = None,
        max_tool_calls: int | None = None,
        max_turns: int | None = None,
    ) -> dict[str, Any]:
        """Execute a Responses API call and (optionally) handle tool calls.

        Returns a dict with:
        - response_id
        - text (assistant text output, if any)
        - findings / analysis_summary (if report_findings was called)
        """

        selected_model = model or self.config.model
        eff = reasoning_effort or self.config.reasoning_effort
        verb = verbosity or self.config.verbosity

        tool_defs = tools if tools is not None else RESPONSES_TOOL_DEFS

        usage_acc = {
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
            "cached_tokens": 0,
            "reasoning_tokens": 0,
        }
        t0 = time.perf_counter()

        def _record_usage(resp) -> None:
            u = _usage_to_dict(getattr(resp, "usage", None))
            if not u:
                return
            for k in usage_acc:
                usage_acc[k] += int(u.get(k, 0) or 0)

        def _create(
            *,
            input_payload: str | list[dict[str, Any]],
            prev_id: str | None,
            include_instructions: bool,
            tool_choice_override: Any | None = None,
        ):
            kwargs: dict[str, Any] = {
                "model": selected_model,
                "input": input_payload,
            }
            if include_instructions:
                kwargs["instructions"] = instructions

            tier = getattr(self.config, "service_tier", "")
            if tier:
                kwargs["service_tier"] = tier

            is_reasoning_model = str(selected_model).startswith("gpt-5") or str(selected_model).startswith("o")
            if is_reasoning_model:
                kwargs["reasoning"] = {"effort": eff}
                kwargs["text"] = {"verbosity": verb}
                if eff == "none":
                    kwargs["temperature"] = self.config.temperature
            else:
                kwargs["temperature"] = self.config.temperature

            if json_mode:
                kwargs.setdefault("text", {})
                kwargs["text"]["format"] = {"type": "json_object"}

            if tool_defs:
                kwargs["tools"] = tool_defs
            choice = tool_choice_override if tool_choice_override is not None else tool_choice
            if choice is not None:
                kwargs["tool_choice"] = choice
            if max_tool_calls is not None:
                kwargs["max_tool_calls"] = max_tool_calls
            if prev_id:
                kwargs["previous_response_id"] = prev_id
            if prompt_cache_key:
                kwargs["prompt_cache_key"] = prompt_cache_key
            if prompt_cache_retention:
                kwargs["prompt_cache_retention"] = prompt_cache_retention

            cache_disabled = False
            for attempt in range(1, RETRY_ATTEMPTS + 1):
                try:
                    resp = self.client.responses.create(**kwargs)
                    _record_usage(resp)
                    return resp
                except NotFoundError:
                    raise RuntimeError(
                        f"Model '{selected_model}' not found or you don't have access. "
                        "Override with --model or RUF_MODEL. "
                        "See: https://developers.openai.com/api/docs/guides/latest-model"
                    )
                except RateLimitError:
                    wait = min(RETRY_BASE_DELAY * (2 ** (attempt - 1)), RETRY_MAX_DELAY)
                    console.print(
                        f"[yellow]  Rate-limited — waiting {wait:.0f}s "
                        f"(attempt {attempt}/{RETRY_ATTEMPTS})[/yellow]"
                    )
                    time.sleep(wait)
                except APIError as exc:
                    # Prompt caching is best-effort; if unsupported, retry once without it.
                    msg = str(exc).lower()
                    if (not cache_disabled) and (
                        "prompt_cache_key" in msg
                        or "prompt_cache_retention" in msg
                        or "prompt cache" in msg
                    ):
                        cache_disabled = True
                        kwargs.pop("prompt_cache_key", None)
                        kwargs.pop("prompt_cache_retention", None)
                        console.print("[yellow]  Prompt caching unsupported — continuing without cache[/yellow]")
                        continue
                    if attempt == RETRY_ATTEMPTS:
                        raise
                    wait = min(RETRY_BASE_DELAY * (2 ** (attempt - 1)), RETRY_MAX_DELAY)
                    console.print(
                        f"[yellow]  API error ({exc}) — waiting {wait:.0f}s "
                        f"(attempt {attempt}/{RETRY_ATTEMPTS})[/yellow]"
                    )
                    time.sleep(wait)
            raise RuntimeError("Exhausted retries after 10 attempts")

        # First request
        resp = _create(input_payload=user_input, prev_id=previous_response_id, include_instructions=True)
        turns = 1
        turn_limit = max_turns or getattr(self.config, "max_tool_iterations", 80)
        forced_finalize = False
        has_report_tool = any(
            isinstance(t, dict) and t.get("type") == "function" and t.get("name") == "report_findings"
            for t in (tool_defs or [])
        )

        # Tool loop (for future navigation mode)
        report_args_retries = 0
        while True:
            if turn_limit and turns >= turn_limit and not forced_finalize and has_report_tool:
                forced_finalize = True
                resp = _create(
                    input_payload=(
                        "Finalize now. If you have any findings, call report_findings with them. "
                        "If there are no findings, call report_findings with an empty findings array "
                        "and a short analysis_summary."
                    ),
                    prev_id=resp.id,
                    include_instructions=True,
                    tool_choice_override={"type": "function", "name": "report_findings"},
                )
                turns += 1
                continue

            # Fast-path: parse report_findings if present.
            parsed = self._parse_report_findings(resp)
            if parsed is not None:
                parsed["response_id"] = resp.id
                parsed["text"] = _response_text(resp)
                parsed["usage"] = dict(usage_acc)
                parsed["elapsed_ms"] = int((time.perf_counter() - t0) * 1000)
                return parsed

            calls = [
                item
                for item in getattr(resp, "output", []) or []
                if getattr(item, "type", None) == "function_call"
            ]
            if not calls:
                return {
                    "response_id": resp.id,
                    "text": _response_text(resp),
                    "usage": dict(usage_acc),
                    "elapsed_ms": int((time.perf_counter() - t0) * 1000),
                }

            tool_outputs: list[dict[str, Any]] = []
            requested_reemit = False
            for call in calls:
                name = getattr(call, "name", "")
                if name == "report_findings":
                    # If the model emitted an invalid tool payload, ask it to re-emit.
                    report_args_retries += 1
                    if report_args_retries <= 2:
                        resp = _create(
                            input_payload=(
                                "Your previous `report_findings` tool arguments were invalid. "
                                "Call `report_findings` again with valid JSON including:\n"
                                "- findings: array\n"
                                "- analysis_summary: string\n"
                            ),
                            prev_id=resp.id,
                            include_instructions=True,
                        )
                        turns += 1
                        requested_reemit = True
                        break

                    return {
                        "response_id": resp.id,
                        "text": _response_text(resp),
                        "findings": [],
                        "analysis_summary": "",
                        "usage": dict(usage_acc),
                        "elapsed_ms": int((time.perf_counter() - t0) * 1000),
                    }

                try:
                    args = json.loads(getattr(call, "arguments", "") or "{}")
                except json.JSONDecodeError:
                    args = {}

                _log_tool_call(name, args)
                result = self.navigator.execute_tool(name, args)
                tool_outputs.append(
                    {
                        "type": "function_call_output",
                        "call_id": getattr(call, "call_id", ""),
                        "output": json.dumps(result),
                    }
                )
            if requested_reemit:
                continue

            # Continue the session with tool outputs; no need to repeat instructions.
            # Responses API does not carry `instructions` across previous_response_id,
            # so we must include them on every turn to maintain behavior/quality.
            resp = _create(input_payload=tool_outputs, prev_id=resp.id, include_instructions=True)
            turns += 1

    @staticmethod
    def _parse_report_findings(resp) -> dict[str, Any] | None:
        for item in getattr(resp, "output", []) or []:
            if getattr(item, "type", None) != "function_call":
                continue
            if getattr(item, "name", None) != "report_findings":
                continue
            try:
                args = json.loads(getattr(item, "arguments", "") or "{}")
            except json.JSONDecodeError:
                return None

            findings = args.get("findings")
            analysis_summary = args.get("analysis_summary")
            if not isinstance(findings, list):
                return None
            if not isinstance(analysis_summary, str):
                return None

            return {"findings": findings, "analysis_summary": analysis_summary}
        return None

