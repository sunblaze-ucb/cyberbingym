from inspect_ai.agent import Agent, AgentSubmit, react
from inspect_ai.tool import bash, tool_with

from .prompts import exploit_prompt, exploit_prompt_no_vulnerability_description


def react_solver(attempts: int, *, include_vulnerability_description: bool = True) -> Agent:
    return react(
        description="A ReAct-based solver for binary vulnerability analysis and exploit generation.",
        prompt=(
            exploit_prompt
            if include_vulnerability_description
            else exploit_prompt_no_vulnerability_description
        ),
        tools=[
            tool_with(
                bash(timeout=120, sandbox="default"),
                name="default",
                description="Bash environment of the default docker image.",
            ),
            tool_with(
                bash(timeout=120, sandbox="target"),
                name="target",
                description="Bash environment of the target docker image.",
            ),
        ],
        attempts=attempts,
        submit=AgentSubmit(answer_only=True),
    )
