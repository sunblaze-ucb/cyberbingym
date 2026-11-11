# CyberBinGym

[![Website](https://img.shields.io/badge/Website-cybergym.io-blue.svg)](https://www.cybergym.io/cyberbingym/)
[![arXiv](https://img.shields.io/badge/arXiv-2611.10723-b31b1b.svg)](https://arxiv.org/abs/2611.10723)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

CyberBinGym is a benchmark for binary-exploitation agents. Each task gives an agent a pair of vulnerable and patched binaries and scores it on proof-of-crash and/or full exploitability against a victim service.

This release ships a curated **100-sample** dataset. The vulnerable/fixed Docker images the dataset references (`lambangaw/cybingym:*`, `n132/arvo:*`) are public on Docker Hub, so the benchmark runs with no private infrastructure.

## Quick start

```bash
# Run these commands from the repository root.
# 1. Install the package and Python deps
uv sync

# 2. API key for whichever model provider you're evaluating
export OPENAI_API_KEY=...      # or ANTHROPIC_API_KEY / MOONSHOT_API_KEY

# 3. Run the default Inspect ReAct-style solver on the full dataset
uv run inspect eval cyberbingym/cyberbingym --model openai/gpt-4o-mini
```

Docker images are pulled automatically per-sample by Inspect on first use; no
separate image-pull step is required. Docker daemon access is required.
The Docker Engine must support `isolated` bridge gateway mode (tested with
Engine 28.2.2). The internal networks require this mode; there is no fallback
to a weaker configuration if the engine rejects it.

## Dataset

`data/dataset.json` ships with 100 curated samples (vulnerability description in `data/<id>/desc.txt`, plus Docker image references in each sample's metadata). You can point Inspect at a subset with `--sample-id`, or replace `data/dataset.json` with the same schema — each entry needs `id`, `target`, `metadata.{analysis_image,valid_image_vul,valid_image_fix,target_binary}`, and `files.{desc.txt}`.

Paths in each record's `files` mapping are relative to `data/dataset.json`, so
`"desc.txt": "368/desc.txt"` resolves to `data/368/desc.txt`.

By default the agent does **not** receive `desc.txt`; it must find the vulnerability from the binaries alone. Pass `-T include_vulnerability_description=true` to give it the description instead.

## Running agents

Select another built-in agent with `agent_type`:

```bash
uv run inspect eval cyberbingym/cyberbingym -T agent_type=openai --model openai/gpt-4o-mini
uv run inspect eval cyberbingym/cyberbingym -T agent_type=claude_code --model anthropic/claude-opus-4-8
uv run inspect eval cyberbingym/cyberbingym -T agent_type=codex --model openai/gpt-5
uv run inspect eval cyberbingym/cyberbingym -T agent_type=kimi_code --model moonshot/kimi-k3
```

Choose the evaluation objective with `evaluation_level`:

```bash
# Default: score crash plus exploitability, and include the victim service.
uv run inspect eval cyberbingym/cyberbingym -T agent_type=codex -T evaluation_level=full --model openai/gpt-5 --turn-limit 1000

# Crash-only: score only /CyberBinGym_workdir/poc_crash and omit the victim service.
# evaluation_level=crash does not support hiding the description, so it must be
# turned back on explicitly.
uv run inspect eval cyberbingym/cyberbingym -T agent_type=codex -T evaluation_level=crash -T include_vulnerability_description=true --model openai/gpt-5
```

`evaluation_level=crash` is currently supported for the CLI-backed agents `claude_code`, `codex`, and `kimi_code`. Those agents receive a restricted `validate_crash_poc` tool that reads only `/CyberBinGym_workdir/poc_crash` and validates it against the benchmark's hidden vulnerable and fixed images. The tool accepts no arguments and does not provide a shell or arbitrary-path access. Its current response includes validation image names and program output; these are not hidden from the agent.

Crash-only runs are diagnostic; `evaluation_level=full` is the benchmark's primary objective. Full CLI runs should use `--turn-limit 1000`.

Persist CLI-agent PoC artifacts to the host with `poc_artifact_dir`. When enabled,
the scorer copies `/CyberBinGym_workdir/poc_crash` and `/CyberBinGym_workdir/poc` from
the default sandbox before cleanup, writes raw bytes unchanged, and stores metadata
beside each file:

```bash
uv run inspect eval cyberbingym/cyberbingym \
  -T agent_type=codex \
  -T evaluation_level=full \
  -T poc_artifact_dir=poc_artifacts/codex-full \
  --model openai/gpt-5 \
  --turn-limit 1000
```

The same output directory can be set with `CYBERBINGYM_POC_ARTIFACT_DIR`. Saved files
are written under `<dir>/<model>/<sample-id>/<sample-uuid-or-epoch>/`.

Run specific samples with Inspect's `--sample-id` selector (comma-separated for
more than one):

```bash
uv run inspect eval cyberbingym/cyberbingym \
  --sample-id 368,14245,19039 \
  -T agent_type=claude_code \
  -T evaluation_level=full \
  --model anthropic/claude-opus-4-8 \
  --reasoning-effort high \
  --turn-limit 1000
```

For the CLI-backed agents, use Inspect's `--turn-limit` to cap model turns. Other
useful limits include `--token-limit`, `--cost-limit`, `--time-limit`, and
`--message-limit`.

Kimi Code needs the native Moonshot provider (`export MOONSHOT_API_KEY=...`). It
defaults to the pinned binary version `0.29.0`; override it with
`-T kimi_code_version=<version>`. Use `inspect trace dump --filter "Kimi Code"`
to inspect agent debug traces.


## Trajectory auditing and reward hacking

Scores are only meaningful if the agent earned them by analysing the binaries
and building an exploit. We audit agent trajectories, and results from
trajectories that reward-hack are invalid and will be excluded.

Automated sandbox and network restrictions reduce these paths but do not
replace the audit. When publishing results, keep the Inspect logs and, where
possible, the PoC artifacts (see `poc_artifact_dir` above) so trajectories can be reviewed.

## Repository layout

```text
src/cyberbingym/
  task.py             # Inspect task, dataset mapping, per-sample Compose config
  scorer.py           # Validation containers, scoring, artifact capture
  memory_limits.py    # Per-container memory allocations
  networking.py       # Internal isolated networks and the proxy's egress network
  model_costs.py      # Model cost overrides
  solvers/            # ReAct, OpenAI SDK, and CLI agent adapters and prompts
  agent_env/          # Dockerfiles, Squid config, victim helper
data/
  dataset.json        # Sample definitions
  <id>/               # Descriptions and target metadata
```

`uv sync` installs the package in editable mode and Inspect loads it through the
`cyberbingym/cyberbingym` entry point. The dataset is external to the package, so
run commands from the repository root.

## Local artifacts

`evals/`, `logs/`, `poc_artifacts/`, and `*.eval` archives are local run artifacts. They are ignored by git and safe to delete between runs, though you may want to keep them for trajectory audits.

## License

The source code is licensed under [MIT](LICENSE).
