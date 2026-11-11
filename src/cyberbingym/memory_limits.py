"""Fixed container allocations whose sum stays within a sample's RAM budget."""

DEFAULT_SAMPLE_MEMORY_MB = 32768
VALIDATION_MEMORY_KEY = "cyberbingym_validation_memory_bytes"


def sample_memory_limits(sample_memory_mb: int = DEFAULT_SAMPLE_MEMORY_MB) -> dict[str, int]:
    """Return byte limits; reserve two validation slots even in crash-only mode."""
    if isinstance(sample_memory_mb, bool) or not isinstance(sample_memory_mb, int) or sample_memory_mb < 1024:
        raise ValueError("sample_memory_mb must be an integer of at least 1024 MiB")
    unit = sample_memory_mb * 1024 * 1024 // 32
    return {
        "default": 16 * unit,
        "target": 4 * unit,
        "victim": 3 * unit,
        "proxy": unit,
        "validation": 4 * unit,
    }
