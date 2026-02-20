from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class Config:
    api_key: str = ""
    model: str = "gpt-5.2"
    base_url: str = "https://api.openai.com/v1"
    # OpenAI service tier: "priority" or "default" (leave empty to omit).
    service_tier: str = "priority"
    temperature: float = 0.1
    max_context_tokens: int = 128_000
    max_tool_iterations: int = 250

    # GPT-5.2 controls (Chat Completions API)
    # https://developers.openai.com/api/docs/guides/latest-model
    #   reasoning_effort: none | low | medium | high | xhigh
    #   verbosity:        low | medium | high
    reasoning_effort: str = "xhigh"
    verbosity: str = "medium"

    # Responses API prompt caching (best-effort; ignored if unsupported)
    prompt_cache_retention: str = "24h"  # "24h" or "in-memory"

    # Optional faster model for navigation/tooling (final findings should still use `model`)
    navigation_model: str = "gpt-5-mini"
    navigation_reasoning_effort: str = "none"
    navigation_verbosity: str = "low"

    supported_extensions: list[str] = field(default_factory=lambda: [
        ".sol", ".vy", ".rs", ".move", ".cairo",
        ".ts", ".js", ".toml", ".yaml", ".yml",
    ])

    ignored_dirs: list[str] = field(default_factory=lambda: [
        "node_modules", ".git", "build", "artifacts",
        "cache", "coverage", "__pycache__", ".vscode",
        "typechain-types", "deployments", ".deps",
        ".venv", "venv", ".env", "env",
        ".tox", ".mypy_cache", ".pytest_cache",
        "dist", "*.egg-info",
        # Rust / Cargo
        "target", "incremental",
        # Misc
        ".DS_Store", "reports", "flycheck*",
        ".VSCodeCounter",
    ])

    def normalize(self) -> Config:
        """Normalize legacy aliases and option spellings in-place."""
        # Legacy model alias used in earlier iterations.
        if self.model == "chatgpt-5.2-extra-high-fast":
            self.model = "gpt-5.2"

        # Normalize prompt cache retention spellings.
        r = (self.prompt_cache_retention or "").strip().lower()
        if r in {"in-memory", "inmemory", "in_mem", "in-memory-cache", "in_memory"}:
            self.prompt_cache_retention = "in-memory"
        elif r in {"24h", "24hr", "24hrs", "1d", "1day", "day"}:
            self.prompt_cache_retention = "24h"

        return self

    @classmethod
    def from_env(cls) -> Config:
        def _int_env(name: str, default: int) -> int:
            try:
                return int(os.environ.get(name, str(default)))
            except ValueError:
                return default

        cfg = cls(
            api_key=os.environ.get("OPENAI_API_KEY", ""),
            model=os.environ.get("RUF_MODEL", "gpt-5.2"),
            navigation_model=os.environ.get("RUF_NAV_MODEL", "gpt-5-mini"),
            base_url=os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1"),
            service_tier=os.environ.get("RUF_SERVICE_TIER", "priority"),
            reasoning_effort=os.environ.get("RUF_REASONING_EFFORT", "xhigh"),
            verbosity=os.environ.get("RUF_VERBOSITY", "medium"),
            navigation_reasoning_effort=os.environ.get("RUF_NAV_REASONING_EFFORT", "none"),
            navigation_verbosity=os.environ.get("RUF_NAV_VERBOSITY", "low"),
            prompt_cache_retention=os.environ.get("RUF_PROMPT_CACHE_RETENTION", "24h"),
            max_tool_iterations=_int_env("RUF_MAX_TOOL_ITERATIONS", 250),
        )
        return cfg.normalize()
