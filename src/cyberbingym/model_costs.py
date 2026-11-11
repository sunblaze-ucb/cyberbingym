from __future__ import annotations

from inspect_ai.model import ModelCost, set_model_cost


GPT_5_6_SOL_COST = ModelCost(
    input=5.0,
    output=30.0,
    input_cache_write=6.25,
    input_cache_read=0.50,
)

CLAUDE_OPUS_5_COST = ModelCost(
    input=5.0,
    output=25.0,
    input_cache_write=6.25,
    input_cache_read=0.50,
)

KIMI_K3_COST = ModelCost(
    input=3.0,
    output=15.0,
    input_cache_write=3.0,
    input_cache_read=0.30,
)

FRONTIER_MODEL_COSTS: dict[str, ModelCost] = {
    "openai/gpt-5.6": GPT_5_6_SOL_COST,
    "gpt-5.6": GPT_5_6_SOL_COST,
    "openai/gpt-5.6-sol": GPT_5_6_SOL_COST,
    "gpt-5.6-sol": GPT_5_6_SOL_COST,
    "anthropic/claude-opus-5": CLAUDE_OPUS_5_COST,
    "claude-opus-5": CLAUDE_OPUS_5_COST,
    "anthropic/claude-opus-4-8": CLAUDE_OPUS_5_COST,
    "claude-opus-4-8": CLAUDE_OPUS_5_COST,
    "moonshot/kimi-k3": KIMI_K3_COST,
    "kimi-k3": KIMI_K3_COST,
    "openai/kimi-k3": KIMI_K3_COST,
    "openai-api/moonshot/kimi-k3": KIMI_K3_COST,
    "openai-api/kimi/kimi-k3": KIMI_K3_COST,
}


def register_frontier_model_costs() -> None:
    for model, cost in FRONTIER_MODEL_COSTS.items():
        try:
            set_model_cost(model, cost)
        except ValueError:
            pass
