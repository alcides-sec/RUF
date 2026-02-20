# RUF — AI Security Auditor for Smart Contracts

RUF is a multi-pass AI audit pipeline that reviews smart-contract codebases with the thoroughness of a senior auditor. It uses OpenAI-compatible models with tool calling to autonomously navigate, read, and analyse source files.

## How It Works

```
Codebase ──▸ Phase Planning ──▸ Per-Phase Audit (×3 passes) ──▸ Holistic Review ──▸ Severity Validation ──▸ Report
```

1. **Phase Planning** — The AI analyses project structure and groups files into logical audit phases (e.g. "Core Protocol", "Access Control", "Oracle Integration"). It explains *why* each grouping was chosen and notes cross-phase dependencies.

2. **Per-Phase Audit (3 passes each)**
   | Pass | Goal |
   |------|------|
   | **Discovery** | Read every file line-by-line, identify all potential issues |
   | **Deep Dive** | Re-examine with adversarial mindset, find subtle / chained attacks |
   | **Validation** | Eliminate false positives, calibrate severities |

   All three passes share memory — each execution sees findings from the previous ones.

3. **Holistic Review** — Cross-phase analysis to catch system-level vulnerabilities that per-phase audits miss (cross-contract reentrancy, privilege escalation chains, economic attacks).

4. **Severity Validation** — A skeptical final pass challenges every severity rating against realistic exploitability and impact.

## Quick Start

```bash
# Install
pip install -e .

# Set your API key
export OPENAI_API_KEY="sk-..."

# Run an audit
ruf audit ./path/to/contracts

# Just scan the project (no audit)
ruf scan ./path/to/contracts
```

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `OPENAI_API_KEY` | — | API key (required) |
| `RUF_MODEL` | `gpt-5.2` | Primary (high-quality) model for findings |
| `RUF_NAV_MODEL` | `gpt-5-mini` | Faster model for planning/navigation-only tasks |
| `OPENAI_BASE_URL` | `https://api.openai.com/v1` | API base URL |
| `RUF_PROMPT_CACHE_RETENTION` | `24h` | Prompt caching retention (`24h` or `in-memory`) |

CLI flags override environment variables:

```bash
ruf audit ./contracts \
    --model gpt-4o \
    --api-key sk-... \
    --output ./reports \
    --temperature 0.1
```

## Output

RUF generates two report files in the output directory:

- **Markdown** — human-readable report with executive summary, methodology, phase breakdowns, and detailed findings.
- **JSON** — machine-readable format for integration with other tools.

Each finding includes:
- Severity (Critical / High / Medium / Low / Informational / Gas)
- Category, file path, line numbers
- Description, impact assessment, recommendation
- Proof of concept (when applicable)
- Severity validation notes from the skeptical review

## Supported Languages

Solidity (`.sol`), Vyper (`.vy`), Rust (`.rs`), Move (`.move`), Cairo (`.cairo`), plus config files (`.toml`, `.yaml`, `.yml`).

## Architecture

```
ruf/
├── cli.py          # Click CLI
├── config.py       # Configuration
├── models.py       # Issue, Phase, AuditReport data models
├── navigator.py    # File-system tools (read, search, outline)
├── ai_client.py    # OpenAI client with tool-calling loop
├── memory.py       # Cross-execution memory management
├── pipeline.py     # Main audit orchestrator
├── prompts.py      # System prompts for each stage
└── report.py       # Markdown & JSON report generation
```
