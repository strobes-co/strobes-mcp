"""Runtime configuration for the Strobes MCP server.

All values come from environment variables so the server can be dropped into
Claude Code / any MCP host without code changes. Production only needs
``STROBES_HOST``, ``STROBES_API_TOKEN`` and ``STROBES_ORGANIZATION_ID``; the
remaining knobs exist for self-hosted / on-prem / local-dev deployments that
sit behind a gateway or speak plain HTTP.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


class ConfigError(RuntimeError):
    """Raised when required configuration is missing."""


def _env(*names: str, default: str | None = None) -> str | None:
    for n in names:
        v = os.getenv(n)
        if v:
            return v
    return default


def _bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Config:
    host: str                      # tenant host, e.g. "acme.strobes.co"
    api_token: str                 # Strobes MasterKey (API token)
    organization_id: str           # org UUID
    base_url: str | None = None    # override scheme+host[:port], e.g. http://localhost
    tenant_host: str | None = None # override the Host header (local/dev)
    verify_tls: bool = True

    @property
    def public_graphql_url(self) -> str:
        base = (self.base_url or f"https://{self.host}").rstrip("/")
        return f"{base}/api/public/graphql/"

    @property
    def host_header(self) -> str:
        return self.tenant_host or self.host


def load_config() -> Config:
    host = _env("STROBES_HOST")
    token = _env("STROBES_API_TOKEN", "STROBES_MASTER_KEY")
    org = _env("STROBES_ORGANIZATION_ID", "STROBES_ORG_ID")
    missing = [
        n
        for n, v in (
            ("STROBES_HOST", host),
            ("STROBES_API_TOKEN", token),
            ("STROBES_ORGANIZATION_ID", org),
        )
        if not v
    ]
    if missing:
        raise ConfigError(
            "Missing required environment variable(s): "
            + ", ".join(missing)
            + ". Set them in your MCP server config (see README)."
        )
    return Config(
        host=host,
        api_token=token,
        organization_id=org,
        base_url=_env("STROBES_BASE_URL"),
        tenant_host=_env("STROBES_TENANT_HOST"),
        verify_tls=_bool("STROBES_VERIFY_TLS", True),
    )
