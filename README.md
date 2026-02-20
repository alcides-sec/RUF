# RUF — Multi-pass AI Security Auditor

RUF is a multi-pass AI audit pipeline that reviews codebases with the thoroughness of a senior auditor. It is optimized for smart contracts and blockchain projects, but the same pipeline can be used for other software audits by adjusting scope (file extensions) and prompts.

## How It Works

```
Codebase ──▸ Phase Planning ──▸ Per-Phase Audit (×2 passes) ──▸ Final Review (global) ──▸ Report
```

1. **Phase Planning** — The AI analyses project structure and groups files into logical audit phases (e.g. "Core Protocol", "Access Control", "Oracle Integration"). It explains *why* each grouping was chosen and notes cross-phase dependencies.

2. **Per-Phase Audit (2 passes each)**
   | Pass | Goal |
   |------|------|
   | **Discovery** | Read every file line-by-line, identify all potential issues |
   | **Validation** | Eliminate false positives, deduplicate, calibrate severities |

   Both passes share context — validation reviews and prunes the discovery candidates for the same phase.

3. **Final Review (global)** — A single final stage that combines cross-phase sanity checks with skeptical validation (dedupe + false positives + severity calibration) and outputs the final client-ready finding set.

## Quick Start

```bash
# Install
pip install -e .

# Set your API key
export OPENAI_API_KEY="sk-..."

# Run an audit
ruf audit ./path/to/codebase

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
- A code snippet in the Markdown report (for quick review)

## Supported Languages

By default, RUF audits smart-contract ecosystems and common supporting code:

- Solidity (`.sol`), Vyper (`.vy`), Rust (`.rs`), Move (`.move`), Cairo (`.cairo`)
- JavaScript/TypeScript (`.js`, `.ts`)
- Configs (`.toml`, `.yaml`, `.yml`)

To audit other codebases (e.g. backend services, apps), extend `Config.supported_extensions` in `ruf/config.py` and adapt prompts in `ruf/prompts.py` to your threat model.

## Architecture

```
ruf/
├── cli.py          # Click CLI
├── config.py       # Configuration
├── models.py       # Issue, Phase, AuditReport data models
├── navigator.py    # File-system tools (read, search, outline)
├── ai_client.py    # OpenAI client with tool-calling loop
├── responses_client.py # Responses API wrapper + telemetry
├── memory.py       # Cross-execution memory management
├── pipeline.py     # Main audit orchestrator
├── prompts.py      # System prompts for each stage
└── report.py       # Markdown & JSON report generation
```
