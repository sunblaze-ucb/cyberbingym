from __future__ import annotations

import atexit
import os
import re
import secrets
import shutil
import tempfile

from pathlib import Path
from typing import Any

from cyberbingym.memory_limits import DEFAULT_SAMPLE_MEMORY_MB, VALIDATION_MEMORY_KEY, sample_memory_limits
from cyberbingym.model_costs import register_frontier_model_costs
from cyberbingym.networking import sample_networks
from cyberbingym.scorer import cyberbingym_crash_scorer, cyberbingym_scorer

from inspect_ai import Task, task
from inspect_ai.dataset import Sample, json_dataset
from inspect_ai.util import (
    CheckpointSampleConfig,
    ComposeBuild,
    ComposeConfig,
    ComposeService,
    SandboxEnvironmentSpec,
)
from pydantic import ValidationError

MAXIMUM_ATTEMPTS = 1
EVALUATION_LEVELS = {"crash", "full"}
CLI_AGENT_TYPES = {"claude_code", "codex", "kimi_code"}
CYBERBINGYM_DIR = Path(__file__).resolve().parent
CHECKPOINT_WORKDIR = "/CyberBinGym_workdir"


def _coerce_legacy_compose_mem_limits(config: dict[str, Any]) -> dict[str, Any]:
    services = config.get("services")
    if not isinstance(services, dict):
        return config

    updated_services: dict[str, Any] | None = None
    for name, service in services.items():
        if not isinstance(service, dict):
            continue
        mem_limit = service.get("mem_limit")
        if isinstance(mem_limit, int) and not isinstance(mem_limit, bool):
            if updated_services is None:
                updated_services = dict(services)
            updated_service = dict(service)
            updated_service["mem_limit"] = str(mem_limit)
            updated_services[name] = updated_service

    if updated_services is None:
        return config

    updated_config = dict(config)
    updated_config["services"] = updated_services
    return updated_config


def _install_legacy_inspect_docker_config_deserializer() -> None:
    """Let Inspect rebuild ComposeConfig sandboxes from logs and checkpoints.

    The pinned Inspect release does not implement ``config_deserialize`` for
    the Docker sandbox, so retrying or resuming a run that uses an in-memory
    ComposeConfig would fail. Integer ``mem_limit`` values written by older
    runs are coerced to the string form ComposeConfig expects.
    """
    from inspect_ai.util._sandbox.docker.docker import DockerSandboxEnvironment

    if "config_deserialize" in DockerSandboxEnvironment.__dict__:
        return

    original_config_deserialize = DockerSandboxEnvironment.config_deserialize

    def config_deserialize(
        _cls: type[DockerSandboxEnvironment], config: dict[str, Any]
    ) -> ComposeConfig:
        try:
            return ComposeConfig.model_validate(
                _coerce_legacy_compose_mem_limits(config)
            )
        except ValidationError:
            return original_config_deserialize(config)

    DockerSandboxEnvironment.config_deserialize = classmethod(config_deserialize)


_install_legacy_inspect_docker_config_deserializer()


def _checkpoint_sample_config(agent_type: str) -> CheckpointSampleConfig:
    """Capture resumable agent state without snapshotting service homes.

    Inspect snapshots each sandbox's default user's home when no paths are
    configured. The target and victim images intentionally give their
    unprivileged ``cyberbingym`` user ``/nonexistent`` as a home directory, so
    that default makes restic fail at the first checkpoint. The artifacts the
    agents need are in the shared work directory; Claude and Kimi also keep
    their resumable CLI conversations under root's home.

    Sample-level configuration customizes checkpointing only. It does not
    enable it: callers still opt in with ``--checkpoint``.
    """
    default_paths = [CHECKPOINT_WORKDIR]
    if agent_type == "claude_code":
        default_paths.append("/root/.claude")
    elif agent_type == "kimi_code":
        default_paths.append("/root/.kimi-code")

    return CheckpointSampleConfig(
        sandbox_paths={
            "default": default_paths,
            "target": [CHECKPOINT_WORKDIR],
            # These services hold no agent work to resume. Explicit opt-out
            # also avoids their intentionally nonexistent cyberbingym home.
            "proxy": [],
            "victim": [],
        }
    )


def _clean_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _normalize_evaluation_level(evaluation_level: str) -> str:
    normalized = (evaluation_level or "full").strip().lower()
    if normalized not in EVALUATION_LEVELS:
        raise ValueError(
            "evaluation_level must be one of "
            f"{sorted(EVALUATION_LEVELS)}, got {evaluation_level!r}"
        )
    return normalized


def _sample_files_for_vulnerability_description(
    files: dict[str, str] | None,
    *,
    include_vulnerability_description: bool,
) -> dict[str, str] | None:
    if include_vulnerability_description or not files:
        return files
    filtered = {name: path for name, path in files.items() if name != "desc.txt"}
    return filtered or None


def _analysis_image_for_patched_binary(
    record: dict[str, Any],
    *,
    include_patched_binary: bool,
) -> str:
    metadata = record.get("metadata") or {}
    analysis_image = metadata.get("analysis_image")

    if include_patched_binary:
        if not analysis_image:
            raise ValueError("Dataset record is missing metadata.analysis_image")
        return analysis_image

    sample_id = _clean_str(record.get("id"))
    if not sample_id:
        raise ValueError(
            "include_patched_binary=False requires a dataset record id "
            "to derive the vulnerable-only analysis image"
        )
    return f"lambangaw/cybingym:{sample_id}-vul"


def _select_solver(
    *,
    agent_type: str,
    kimi_code_version: str,
    evaluation_level: str,
    include_vulnerability_description: bool,
    include_patched_binary: bool,
):
    if agent_type == "openai":
        from cyberbingym.solvers.openai_agent import openai_agent

        return openai_agent()
    if agent_type == "claude_code":
        from cyberbingym.solvers.swe_agents import claude_code_solver

        return claude_code_solver(
            evaluation_level=evaluation_level,
            include_vulnerability_description=include_vulnerability_description,
            include_patched_binary=include_patched_binary,
        )
    if agent_type == "codex":
        from cyberbingym.solvers.swe_agents import codex_cli_solver

        return codex_cli_solver(
            evaluation_level=evaluation_level,
            include_vulnerability_description=include_vulnerability_description,
            include_patched_binary=include_patched_binary,
        )
    if agent_type == "kimi_code":
        from cyberbingym.solvers.swe_agents import kimi_code_solver

        return kimi_code_solver(
            version=kimi_code_version,
            evaluation_level=evaluation_level,
            include_vulnerability_description=include_vulnerability_description,
            include_patched_binary=include_patched_binary,
        )
    from cyberbingym.solvers.react import react_solver

    return react_solver(
        attempts=MAXIMUM_ATTEMPTS,
        include_vulnerability_description=include_vulnerability_description,
    )


_CONTEXT_ROOT_PREFIX = "cyberbingym-build-"
_context_root: Path | None = None


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _sweep_stale_build_roots() -> None:
    """Remove build-context roots left behind by crashed or killed runs."""
    pattern = re.compile(rf"^{re.escape(_CONTEXT_ROOT_PREFIX)}(\d+)-")
    for entry in Path(tempfile.gettempdir()).glob(f"{_CONTEXT_ROOT_PREFIX}*"):
        match = pattern.match(entry.name)
        if match and not _pid_alive(int(match.group(1))):
            shutil.rmtree(entry, ignore_errors=True)


def cleanup_build_contexts() -> None:
    """Delete every build context (and the flags in their Dockerfiles)."""
    global _context_root
    if _context_root is not None:
        shutil.rmtree(_context_root, ignore_errors=True)
        _context_root = None


def _new_build_context() -> Path:
    """Create a sample build context owned by this process's lifecycle.

    Contexts live under one 0700 root that is removed at process exit, not
    after each sample: Inspect rebuilds sandboxes from the context on sample
    retry, and a resumed run re-creates the dataset (new contexts, new flags)
    in a fresh process, so nothing here needs to outlive the run.
    """
    global _context_root
    if _context_root is None:
        _sweep_stale_build_roots()
        _context_root = Path(
            tempfile.mkdtemp(prefix=f"{_CONTEXT_ROOT_PREFIX}{os.getpid()}-")
        )
        atexit.register(cleanup_build_contexts)
    return Path(tempfile.mkdtemp(prefix="agent-env-", dir=_context_root))


def create_binary_sample(*args: Any, **kwargs: Any) -> Sample:
    build_context = _new_build_context()
    try:
        return _create_binary_sample(build_context, *args, **kwargs)
    except BaseException:
        # Failed setup must not leave a context (possibly holding a flag).
        shutil.rmtree(build_context, ignore_errors=True)
        raise


def _create_binary_sample(
    build_context: Path,
    prompt: str,
    prebuilt_base_image: str,
    *,
    sample_id: str | int | None = None,
    metadata: dict[str, Any] | None = None,
    files: dict[str, str] | None = None,
    evaluation_level: str = "full",
    include_patched_binary: bool = True,
    sample_memory_mb: int = DEFAULT_SAMPLE_MEMORY_MB,
    checkpoint: CheckpointSampleConfig | None = None,
) -> Sample:
    evaluation_level = _normalize_evaluation_level(evaluation_level)
    memory_limits = sample_memory_limits(sample_memory_mb)
    metadata = {**(metadata or {}), VALIDATION_MEMORY_KEY: memory_limits["validation"]}
    source_context = CYBERBINGYM_DIR / "agent_env"
    shutil.copytree(source_context, build_context, dirs_exist_ok=True)

    dockerfile_default = build_context / "Dockerfile.default"
    vulnerable_binary_source = "/out-vul" if include_patched_binary else "/out"
    dockerfile_default_text = dockerfile_default.read_text().replace(
        "COPY --from=${TARGET_BASE_IMAGE} /out-vul /out-vul",
        f"COPY --from={prebuilt_base_image} {vulnerable_binary_source} /out-vul",
        1,
    )
    if include_patched_binary:
        dockerfile_default_text = dockerfile_default_text.replace(
            "COPY --from=${TARGET_BASE_IMAGE} /out-fix /out-fix",
            f"COPY --from={prebuilt_base_image} /out-fix /out-fix",
            1,
        )
    else:
        dockerfile_default_text = dockerfile_default_text.replace(
            "COPY --from=${TARGET_BASE_IMAGE} /out-fix /out-fix\n",
            "",
            1,
        )
    dockerfile_default.write_text(dockerfile_default_text)
    dockerfile_target = build_context / "Dockerfile.target"
    dockerfile_target_text = dockerfile_target.read_text().replace(
        "FROM ${BASE_IMAGE}",
        f"FROM {prebuilt_base_image}",
        1,
    )
    if not include_patched_binary:
        dockerfile_target_text = dockerfile_target_text.replace(
            f"FROM {prebuilt_base_image}\n",
            f"FROM {prebuilt_base_image}\n\nRUN cp -a /out /out-vul\n",
            1,
        )
    dockerfile_target.write_text(dockerfile_target_text)

    flag = secrets.token_hex(32)
    proxy_env = {
        # HTTP proxy used by curl/wget/apt/pip/etc.
        "HTTP_PROXY": "http://proxy:3128",
        "HTTPS_PROXY": "http://proxy:3128",
        "http_proxy": "http://proxy:3128",
        "https_proxy": "http://proxy:3128",
        # Benchmark-local traffic must not go through Squid.
        "NO_PROXY": "localhost,127.0.0.1,target,victim,proxy",
        "no_proxy": "localhost,127.0.0.1,target,victim,proxy",
        # Force normal pip installs to use the official PyPI index.
        "PIP_INDEX_URL": "https://pypi.org/simple",
    }
    services = {
        "default": ComposeService(
            build=ComposeBuild(
                context=str(build_context),
                dockerfile="Dockerfile.default",
            ),
            init=True,
            command="tail -f /dev/null",
            networks=["benchmark_net", "proxy_net"],
            environment=proxy_env,  # type: ignore
            depends_on=["proxy"],
        ),
        "target": ComposeService(
            build=ComposeBuild(
                context=str(build_context),
                dockerfile="Dockerfile.target",
            ),
            init=True,
            command="tail -f /dev/null",
            networks=["benchmark_net", "proxy_net"],
            environment=proxy_env,  # type: ignore
            depends_on=["proxy"],
        ),
        "proxy": ComposeService(
            build=ComposeBuild(
                context=str(build_context),
                dockerfile="Dockerfile.proxy",
            ),
            init=True,
            networks=["proxy_net", "internet_net"],
            expose=[3128],
        ),
    }

    if evaluation_level == "full":
        catflag_helper_id = secrets.token_hex(8)
        dockerfile_victim = build_context / "Dockerfile.victim"
        dockerfile_victim.write_text(
            dockerfile_victim.read_text().replace(
                "FROM ${BASE_IMAGE}",
                f"FROM {prebuilt_base_image}",
                2,
            ).replace(
                "${CYBERBINGYM_FLAG}",
                f"flag{{{flag}}}",
                1,
            ).replace(
                "ARG CYBERBINGYM_CATFLAG_HELPER_ID=0000000000000000",
                f"ARG CYBERBINGYM_CATFLAG_HELPER_ID={catflag_helper_id}",
                1,
            )
        )
        if not include_patched_binary:
            dockerfile_victim_text = dockerfile_victim.read_text().replace(
                f"FROM {prebuilt_base_image}\n\nRUN apt-get",
                f"FROM {prebuilt_base_image}\n\nRUN cp -a /out /out-vul\n\nRUN apt-get",
                1,
            )
            dockerfile_victim.write_text(dockerfile_victim_text)
        services["victim"] = ComposeService(
            build=ComposeBuild(
                context=str(build_context),
                dockerfile="Dockerfile.victim",
            ),
            init=True,
            networks=["benchmark_net"],
        )

    for name, service in services.items():
        limit = str(memory_limits[name])
        # Inspect log deserialization requires compose mem_limit values as strings.
        service.mem_limit = limit
        # Docker defines memswap_limit as RAM + swap; equality disables swap.
        service.memswap_limit = limit

    config = ComposeConfig(
        services=services,
        networks=sample_networks(),
    )

    return Sample(
        id=sample_id,
        input=prompt,
        target=flag,
        metadata=metadata,
        sandbox=SandboxEnvironmentSpec(type="docker", config=config),
        files=files,
        checkpoint=checkpoint,
    )


@task
def cyberbingym(
    agent_type: str = "basic",
    kimi_code_version: str = "0.29.0",
    evaluation_level: str = "full",
    include_vulnerability_description: bool = False,
    include_patched_binary: bool = True,
    sample_memory_mb: int | None = None,
    poc_artifact_dir: str = "",
):
    memory_budget = DEFAULT_SAMPLE_MEMORY_MB if sample_memory_mb is None else sample_memory_mb
    sample_memory_limits(memory_budget)
    register_frontier_model_costs()

    evaluation_level = _normalize_evaluation_level(evaluation_level)
    if evaluation_level == "crash" and agent_type not in CLI_AGENT_TYPES:
        raise ValueError(
            "evaluation_level=crash is currently supported only for "
            f"agent_type in {sorted(CLI_AGENT_TYPES)}; got {agent_type!r}"
        )
    if not include_vulnerability_description and evaluation_level != "full":
        raise ValueError(
            "include_vulnerability_description=False is currently supported "
            "only for evaluation_level='full'"
        )
    if not include_patched_binary:
        if evaluation_level != "full":
            raise ValueError(
                "include_patched_binary=False is currently supported "
                "only for evaluation_level='full'"
            )
        if agent_type not in CLI_AGENT_TYPES:
            raise ValueError(
                "include_patched_binary=False is currently supported "
                f"only for CLI agent types {sorted(CLI_AGENT_TYPES)}; "
                f"got {agent_type!r}"
            )

    def build_sample(record: dict[str, Any]) -> Sample:
        metadata = record.get("metadata") or {}
        analysis_image = _analysis_image_for_patched_binary(
            record,
            include_patched_binary=include_patched_binary,
        )

        return create_binary_sample(
            prompt=record["input"],
            prebuilt_base_image=analysis_image,
            sample_id=record.get("id"),
            metadata=metadata,
            files=_sample_files_for_vulnerability_description(
                record.get("files"),
                include_vulnerability_description=include_vulnerability_description,
            ),
            evaluation_level=evaluation_level,
            include_patched_binary=include_patched_binary,
            sample_memory_mb=memory_budget,
            checkpoint=_checkpoint_sample_config(agent_type),
        )

    dataset = json_dataset("data/dataset.json", sample_fields=build_sample)

    return Task(
        dataset=dataset,
        solver=_select_solver(
            agent_type=agent_type,
            kimi_code_version=kimi_code_version,
            evaluation_level=evaluation_level,
            include_vulnerability_description=include_vulnerability_description,
            include_patched_binary=include_patched_binary,
        ),
        scorer=cyberbingym_crash_scorer(
            poc_artifact_dir=poc_artifact_dir,
        ) if evaluation_level == "crash" else cyberbingym_scorer(
            poc_artifact_dir=poc_artifact_dir,
        ),
        fail_on_error=False,
    )
