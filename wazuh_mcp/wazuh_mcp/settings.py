"""Configuration for the read-only Wazuh MCP server.

Values come from environment variables, falling back to lab/readonly.env
(written by `lab/lab.sh users`). Only the read-only identities are ever loaded;
admin credentials (lab/admin.env) are never read here.

LAB-only guard: the API and indexer URLs must point at an allowlisted host
(loopback or the lab's compose service names). Anything else is refused, so
the server cannot be pointed at a real/production Wazuh by accident.
"""

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

DEFAULT_ENV_FILE = Path(__file__).resolve().parents[2] / "lab" / "readonly.env"
DEFAULT_ALLOWED_HOSTS = "127.0.0.1,localhost,wazuh.manager,wazuh.indexer"

REQUIRED_KEYS = (
    "WAZUH_API_URL",
    "WAZUH_API_USER",
    "WAZUH_API_PASSWORD",
    "WAZUH_API_CA",
    "WAZUH_INDEXER_URL",
    "WAZUH_INDEXER_USER",
    "WAZUH_INDEXER_PASSWORD",
    "WAZUH_INDEXER_CA",
)


class LabOnlyError(RuntimeError):
    """Raised when the configuration points outside the local lab."""


@dataclass(frozen=True)
class Settings:
    api_url: str
    api_user: str
    api_password: str = field(repr=False)
    api_ca: str = ""
    indexer_url: str = ""
    indexer_user: str = ""
    indexer_password: str = field(default="", repr=False)
    indexer_ca: str = ""
    # TLS name of the indexer certificate; lets us verify the hostname while
    # connecting to 127.0.0.1 (same as `curl --resolve wazuh.indexer:9200:...`).
    indexer_tls_name: str = "wazuh.indexer"


def read_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip("'\"")
    return values


def check_lab_host(url: str, allowed: set[str]) -> None:
    host = urlparse(url).hostname or ""
    if host not in allowed:
        raise LabOnlyError(
            f"refusing to connect to {host!r}: only lab hosts are allowed "
            f"({', '.join(sorted(allowed))}). Set WAZUH_ALLOWED_HOSTS only for "
            "another local lab, never for a production Wazuh."
        )


def load_settings(environ: Mapping[str, str] | None = None) -> Settings:
    environ = os.environ if environ is None else environ
    env_file = Path(environ.get("WAZUH_ENV_FILE", DEFAULT_ENV_FILE))
    file_values = read_env_file(env_file)

    def get(key: str, default: str = "") -> str:
        return environ.get(key) or file_values.get(key) or default

    missing = [key for key in REQUIRED_KEYS if not get(key)]
    if missing:
        raise RuntimeError(
            f"missing Wazuh settings {missing}; run `lab/lab.sh users` to create "
            f"{env_file} or set them as environment variables"
        )

    allowed = {
        h.strip() for h in get("WAZUH_ALLOWED_HOSTS", DEFAULT_ALLOWED_HOSTS).split(",")
    }
    allowed.discard("")
    for key in ("WAZUH_API_URL", "WAZUH_INDEXER_URL"):
        check_lab_host(get(key), allowed)

    return Settings(
        api_url=get("WAZUH_API_URL").rstrip("/"),
        api_user=get("WAZUH_API_USER"),
        api_password=get("WAZUH_API_PASSWORD"),
        api_ca=get("WAZUH_API_CA"),
        indexer_url=get("WAZUH_INDEXER_URL").rstrip("/"),
        indexer_user=get("WAZUH_INDEXER_USER"),
        indexer_password=get("WAZUH_INDEXER_PASSWORD"),
        indexer_ca=get("WAZUH_INDEXER_CA"),
        indexer_tls_name=get("WAZUH_INDEXER_TLS_NAME", "wazuh.indexer"),
    )
