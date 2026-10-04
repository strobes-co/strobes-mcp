"""Thin wrapper around ``strobes_gql_client`` for the public GraphQL surface.

The public endpoint (``/api/public/graphql/``) is authenticated with a Strobes
MasterKey and exposes assets, findings (bugs), engagements, comments and
reports. We reuse the official client so all the per-operation field pinning
(``BUG_FULL_FIELDS`` etc.) and the gateway-timeout handling come for free.
"""

from __future__ import annotations

import logging
from functools import lru_cache

import requests
from sgqlc.endpoint.requests import RequestsEndpoint
from strobes_gql_client.client import StrobesGQLClient

from .config import Config, load_config

logger = logging.getLogger("strobes_mcp.client")


def build_client(cfg: Config) -> StrobesGQLClient:
    """Return a ``StrobesGQLClient`` wired to ``cfg``.

    For a normal SaaS host (``STROBES_HOST`` only) this is just the stock
    client. When ``STROBES_BASE_URL`` / ``STROBES_TENANT_HOST`` are set (local
    dev, on-prem behind a gateway, plain HTTP) we rebuild the sgqlc endpoint so
    requests go to the override URL while still carrying the right ``Host``
    header for tenant resolution.
    """
    client = StrobesGQLClient(
        host=cfg.host, api_token=cfg.api_token, verify=cfg.verify_tls
    )
    needs_override = cfg.base_url or cfg.tenant_host or not cfg.verify_tls
    if needs_override:
        session = requests.Session()
        session.verify = cfg.verify_tls
        headers = dict(client.headers)
        headers["Host"] = cfg.host_header
        client.graphql_url = cfg.public_graphql_url
        client.endpoint = RequestsEndpoint(
            cfg.public_graphql_url, headers, session=session
        )
    return client


@lru_cache(maxsize=1)
def get_context() -> tuple[StrobesGQLClient, Config]:
    cfg = load_config()
    return build_client(cfg), cfg
