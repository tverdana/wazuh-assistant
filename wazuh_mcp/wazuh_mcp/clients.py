"""Read-only HTTP clients for the Wazuh server API and the Wazuh indexer.

Defense in depth on top of the RBAC of the lab identities:
- WazuhApi exposes only GET, and only for an allowlist of path prefixes
  (the single POST is the login that obtains a JWT).
- WazuhIndexer exposes only `_search` on wazuh-alerts-*.
There is no generic request method, so no tool can issue a write call even if
the read-only role were misconfigured.
"""

import asyncio
import ssl
import time

import httpx

from wazuh_mcp.settings import Settings

ALERTS_INDEX = "wazuh-alerts-*"
API_GET_PREFIXES = ("/agents", "/rules", "/sca/", "/mitre/")
# Wazuh JWTs live 900 s by default; refresh well before that.
TOKEN_TTL_SECONDS = 600
TIMEOUT = httpx.Timeout(connect=5.0, read=20.0, write=10.0, pool=5.0)


class WazuhError(Exception):
    """A failure with a message that is safe to show to the agent/user."""


def _ssl_context(cafile: str, *, check_hostname: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=cafile)
    ctx.check_hostname = check_hostname
    # The Wazuh-generated root CA has no keyUsage extension, which the strict
    # X.509 mode (default since Python 3.13) rejects. The chain is still verified.
    ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    return ctx


def _raise_for_status(resp: httpx.Response, service: str) -> None:
    if resp.status_code < 400:
        return
    if resp.status_code in (401, 403):
        raise WazuhError(
            f"{service} denied the request for the read-only user "
            f"(HTTP {resp.status_code})"
        )
    if resp.status_code == 404:
        raise WazuhError(f"{service}: not found")
    raise WazuhError(f"{service} returned HTTP {resp.status_code}")


async def _send(client: httpx.AsyncClient, service: str, method: str, url: str, **kw):
    try:
        return await client.request(method, url, **kw)
    except httpx.TimeoutException as e:
        raise WazuhError(f"{service} timed out, try again later") from e
    except httpx.TransportError as e:
        raise WazuhError(
            f"cannot reach the {service} (is the lab up? `lab/lab.sh up`): "
            f"{type(e).__name__}"
        ) from e


class WazuhApi:
    """GET-only client for the Wazuh server API (port 55000)."""

    def __init__(
        self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None
    ):
        self._user = settings.api_user
        self._password = settings.api_password
        # The API cert is self-signed (CN=wazuh.com): it is pinned as the only
        # trust anchor, so the hostname check is not needed.
        verify = (
            True if transport else _ssl_context(settings.api_ca, check_hostname=False)
        )
        self._client = httpx.AsyncClient(
            base_url=settings.api_url,
            verify=verify,
            transport=transport,
            timeout=TIMEOUT,
        )
        self._token: str | None = None
        self._token_expires = 0.0
        self._lock = asyncio.Lock()

    async def _get_token(self, *, refresh: bool = False) -> str:
        async with self._lock:
            if self._token and not refresh and time.monotonic() < self._token_expires:
                return self._token
            resp = await _send(
                self._client,
                "Wazuh API",
                "POST",
                "/security/user/authenticate",
                auth=(self._user, self._password),
            )
            if resp.status_code != 200:
                raise WazuhError(f"Wazuh API login failed (HTTP {resp.status_code})")
            self._token = resp.json()["data"]["token"]
            self._token_expires = time.monotonic() + TOKEN_TTL_SECONDS
            return self._token

    async def get(self, path: str, **params) -> dict:
        if not path.startswith(API_GET_PREFIXES) or ".." in path:
            raise WazuhError(f"blocked: {path} is not an allowed read-only API path")
        params = {k: v for k, v in params.items() if v is not None}
        for attempt in range(2):
            token = await self._get_token(refresh=attempt > 0)
            resp = await _send(
                self._client,
                "Wazuh API",
                "GET",
                path,
                params=params,
                headers={"Authorization": f"Bearer {token}"},
            )
            if resp.status_code != 401:
                break
        _raise_for_status(resp, "Wazuh API")
        return resp.json()

    async def items(self, path: str, **params) -> tuple[list[dict], int]:
        data = (await self.get(path, **params)).get("data", {})
        return data.get("affected_items", []), data.get("total_affected_items", 0)

    async def aclose(self) -> None:
        await self._client.aclose()


class WazuhIndexer:
    """Search-only client for wazuh-alerts-* on the Wazuh indexer (port 9200)."""

    def __init__(
        self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None
    ):
        verify = (
            True
            if transport
            else _ssl_context(settings.indexer_ca, check_hostname=True)
        )
        self._client = httpx.AsyncClient(
            base_url=settings.indexer_url,
            verify=verify,
            transport=transport,
            timeout=TIMEOUT,
            auth=(settings.indexer_user, settings.indexer_password),
        )
        # Verify the certificate against its real name while dialing 127.0.0.1.
        self._extensions = (
            {"sni_hostname": settings.indexer_tls_name}
            if settings.indexer_tls_name
            else {}
        )

    async def search(self, body: dict) -> dict:
        resp = await _send(
            self._client,
            "Wazuh indexer",
            "POST",
            f"/{ALERTS_INDEX}/_search",
            json=body,
            extensions=self._extensions,
        )
        _raise_for_status(resp, "Wazuh indexer")
        return resp.json()

    async def aclose(self) -> None:
        await self._client.aclose()
