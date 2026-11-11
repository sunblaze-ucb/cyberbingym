"""Network boundaries for the per-sample Compose project."""

from typing import Any


def sample_networks() -> dict[str, dict[str, Any]]:
    """Keep local services connected without a Docker-assigned host gateway IP.

    The proxy alone joins the outward-facing bridge. Unsupported Docker
    gateway options must fail setup rather than silently weaken this policy.
    """
    networks = {
        name: {
            "driver": "bridge",
            "internal": True,
            "driver_opts": {
                "com.docker.network.bridge.gateway_mode_ipv4": "isolated",
                "com.docker.network.bridge.gateway_mode_ipv6": "isolated",
            },
        }
        for name in ("benchmark_net", "proxy_net")
    }
    networks["internet_net"] = {"driver": "bridge"}
    return networks
