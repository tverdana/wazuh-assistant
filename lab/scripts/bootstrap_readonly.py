"""Create the two read-only identities used by the Wazuh assistant (LAB only).

1. Wazuh server API user  `assistant_api_ro`  -> custom role `assistant_readonly`
   whose policies grant only the *:read actions the MCP tools need.
2. Wazuh indexer user     `assistant_idx_ro`  -> role `assistant_alerts_read`
   with the `read` action group on `wazuh-alerts-*` and nothing else.

Admin (bootstrap) credentials come from lab/admin.env. The generated read-only
credentials are written to lab/readonly.env (gitignored, mode 600). Passwords
are never printed. Safe to re-run: existing objects are reused, and a stored
password is kept as long as it still authenticates.

Stdlib only:  python3 -I lab/scripts/bootstrap_readonly.py
"""

import base64
import json
import os
import secrets
import ssl
import string
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

LAB_DIR = Path(__file__).resolve().parent.parent
ADMIN_ENV = LAB_DIR / "admin.env"
READONLY_ENV = LAB_DIR / "readonly.env"
API_CERT = LAB_DIR / "certs" / "wazuh-api.crt"
INDEXER_CA = LAB_DIR / "certs" / "root-ca.pem"
MANAGER_CONTAINER = "wazuh-lab-wazuh.manager-1"

API_URL = "https://127.0.0.1:55000"
INDEXER_URL = "https://127.0.0.1:9200"

API_USER = "assistant_api_ro"
API_ROLE = "assistant_readonly"
# One policy per resource type (Wazuh validates action/resource pairs).
API_POLICIES = {
    "assistant_ro_agents": {
        "actions": [
            "agent:read",
            "sca:read",
            "syscheck:read",
            "rootcheck:read",
            "syscollector:read",
        ],
        "resources": ["agent:id:*"],
        "effect": "allow",
    },
    "assistant_ro_rules": {
        "actions": ["rules:read"],
        "resources": ["rule:file:*"],
        "effect": "allow",
    },
    "assistant_ro_decoders": {
        "actions": ["decoders:read"],
        "resources": ["decoder:file:*"],
        "effect": "allow",
    },
    "assistant_ro_mitre_manager": {
        "actions": ["mitre:read", "manager:read"],
        "resources": ["*:*:*"],
        "effect": "allow",
    },
}

INDEXER_USER = "assistant_idx_ro"
INDEXER_ROLE = "assistant_alerts_read"
INDEXER_ROLE_BODY = {
    "description": "Wazuh assistant: read-only access to wazuh-alerts-* only",
    "cluster_permissions": [],
    "index_permissions": [
        {"index_patterns": ["wazuh-alerts-*"], "allowed_actions": ["read"]}
    ],
}


def load_env(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    if not path.exists():
        return env
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        env[key.strip()] = value.strip().strip("'\"")
    return env


def new_password() -> str:
    """32 chars with upper, lower, digit and symbol (Wazuh API policy)."""
    symbols = ".-+@#%"
    alphabet = string.ascii_letters + string.digits + symbols
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(32))
        if (
            any(c.isupper() for c in pw)
            and any(c.islower() for c in pw)
            and any(c.isdigit() for c in pw)
            and sum(c in symbols for c in pw) >= 2
        ):
            return pw


def pinned_context(cafile: Path) -> ssl.SSLContext:
    # Verify the chain against the lab CA / pinned self-signed cert. Hostname
    # check is off because the lab certs are issued for container names.
    ctx = ssl.create_default_context(cafile=str(cafile))
    ctx.check_hostname = False
    # Python 3.13+ enables strict X.509 checks by default; the Wazuh-generated
    # root CA has no keyUsage extension, which strict mode rejects.
    ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    return ctx


def call(method, url, ctx, *, basic=None, token=None, body=None):
    headers = {"Content-Type": "application/json"}
    if basic:
        raw = f"{basic[0]}:{basic[1]}".encode()
        headers["Authorization"] = "Basic " + base64.b64encode(raw).decode()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as err:
        payload = err.read()
        try:
            return err.code, json.loads(payload or b"{}")
        except json.JSONDecodeError:
            return err.code, {"raw": payload.decode(errors="replace")[:300]}


def must(status, payload, what):
    if status >= 300:
        sys.exit(f"FAILED {what}: HTTP {status} {json.dumps(payload)[:500]}")
    return payload


def fetch_api_cert() -> None:
    pem = subprocess.run(
        ["docker", "exec", MANAGER_CONTAINER, "cat",
         "/var/ossec/api/configuration/ssl/server.crt"],
        check=True, capture_output=True, text=True,
    ).stdout
    API_CERT.parent.mkdir(exist_ok=True)
    API_CERT.write_text(pem)


# --------------------------------------------------------------------------
# Wazuh server API (RBAC)
# --------------------------------------------------------------------------
def api_token(ctx, user, password):
    status, payload = call(
        "POST", f"{API_URL}/security/user/authenticate", ctx, basic=(user, password)
    )
    return payload["data"]["token"] if status == 200 else None


def api_items(ctx, token, path):
    # On first start the manager is busy (vulnerability feeds) and the API may
    # answer 500 / error 3021 "Timeout executing API request"; GETs are safe to retry.
    for _ in range(6):
        status, payload = call("GET", f"{API_URL}{path}?limit=500", ctx, token=token)
        if not (status == 500 and payload.get("error") == 3021):
            break
        time.sleep(5)
    return must(status, payload, path)["data"]["affected_items"]


def api_create(ctx, token, path, body, key, value):
    """POST and return the created item; if it already exists (e.g. an earlier
    POST timed out but was committed), look it up by `key` instead."""
    payload = must(*call("POST", f"{API_URL}{path}", ctx, token=token, body=body),
                   f"create {path} {value}")
    items = payload["data"]["affected_items"]
    if items:
        return items[0]
    found = [i for i in api_items(ctx, token, path) if i[key] == value]
    if not found:
        sys.exit(f"FAILED create {path} {value}: {json.dumps(payload)[:500]}")
    return found[0]


def setup_api_user(ctx, admin, password) -> None:
    token = api_token(ctx, *admin)
    if not token:
        sys.exit("FAILED: Wazuh API admin login (is the lab up? check admin.env)")

    def same(a, b):
        return all(sorted(a[k]) == sorted(b[k]) for k in ("actions", "resources")) \
            and a["effect"] == b["effect"]

    all_policies = api_items(ctx, token, "/security/policies")
    existing = {p["name"]: p for p in all_policies}
    policy_ids = []
    for name, policy in API_POLICIES.items():
        # Wazuh rejects two policies with the same body (error 4009), so an
        # identical built-in policy (e.g. rules_read_rules) is reused as is.
        twin = next((p for p in all_policies if same(p["policy"], policy)), None)
        if twin:
            pid = twin["id"]
            if twin["name"] != name:
                print(f"[api] reusing identical policy {twin['name']} for {name}")
        elif name in existing:
            pid = existing[name]["id"]
            must(*call("PUT", f"{API_URL}/security/policies/{pid}", ctx, token=token,
                       body={"policy": policy}), f"update policy {name}")
        else:
            pid = api_create(ctx, token, "/security/policies",
                             {"name": name, "policy": policy}, "name", name)["id"]
        policy_ids.append(pid)

    roles = {r["name"]: r for r in api_items(ctx, token, "/security/roles")}
    if API_ROLE in roles:
        role_id = roles[API_ROLE]["id"]
    else:
        role_id = api_create(ctx, token, "/security/roles",
                             {"name": API_ROLE}, "name", API_ROLE)["id"]
    linked = set(roles.get(API_ROLE, {}).get("policies", []))
    missing = [str(p) for p in policy_ids if p not in linked]
    if missing:
        must(*call("POST", f"{API_URL}/security/roles/{role_id}/policies"
                   f"?policy_ids={','.join(missing)}", ctx, token=token),
             "link policies to role")

    users = {u["username"]: u for u in api_items(ctx, token, "/security/users")}
    if API_USER not in users:
        user = api_create(ctx, token, "/security/users",
                          {"username": API_USER, "password": password},
                          "username", API_USER)
    else:
        user = users[API_USER]
        if not api_token(ctx, API_USER, password):
            must(*call("PUT", f"{API_URL}/security/users/{user['id']}", ctx,
                       token=token, body={"password": password}), "reset API password")
    if role_id not in user.get("roles", []):
        must(*call("POST", f"{API_URL}/security/users/{user['id']}/roles"
                   f"?role_ids={role_id}", ctx, token=token), "assign role")

    # Wazuh revokes tokens issued in the same second as an RBAC change.
    time.sleep(2)
    ro_token = api_token(ctx, API_USER, password)
    if not ro_token:
        sys.exit("FAILED: read-only API user cannot log in")
    me = must(*call("GET", f"{API_URL}/security/users/me", ctx, token=ro_token), "me")
    info = me["data"]["affected_items"][0]
    print(f"[api] user={info['username']} roles={info['roles']} "
          f"allow_run_as={info.get('allow_run_as')} policies={sorted(API_POLICIES)}")


# --------------------------------------------------------------------------
# Wazuh indexer (OpenSearch security plugin)
# --------------------------------------------------------------------------
def setup_indexer_user(ctx, admin, password) -> None:
    sec = f"{INDEXER_URL}/_plugins/_security/api"
    must(*call("PUT", f"{sec}/roles/{INDEXER_ROLE}", ctx, basic=admin,
               body=INDEXER_ROLE_BODY), "indexer role")
    must(*call("PUT", f"{sec}/internalusers/{INDEXER_USER}", ctx, basic=admin,
               body={"password": password, "backend_roles": [],
                     "description": "Wazuh assistant read-only (alerts)"}),
         "indexer user")
    must(*call("PUT", f"{sec}/rolesmapping/{INDEXER_ROLE}", ctx, basic=admin,
               body={"users": [INDEXER_USER]}), "indexer role mapping")
    # Lab hardening: the demo security config maps `own_index` (indices_all on
    # an index named like the user + cluster_composite_ops) to every user "*",
    # which would give our read-only user a writable index. Drop the wildcard.
    must(*call("PUT", f"{sec}/rolesmapping/own_index", ctx, basic=admin,
               body={"users": [], "description": "wildcard removed by wazuh-assistant lab"}),
         "own_index mapping")

    info = must(*call("GET", f"{INDEXER_URL}/_plugins/_security/authinfo", ctx,
                      basic=(INDEXER_USER, password)), "indexer authinfo")
    print(f"[indexer] user={info['user_name']} roles={info['roles']} "
          f"index_permissions={INDEXER_ROLE_BODY['index_permissions']}")


def main() -> None:
    admin_env = load_env(ADMIN_ENV)
    if not admin_env:
        sys.exit("lab/admin.env missing — run ./lab.sh setup first")
    stored = load_env(READONLY_ENV)
    api_pw = stored.get("WAZUH_API_PASSWORD") or new_password()
    idx_pw = stored.get("WAZUH_INDEXER_PASSWORD") or new_password()

    fetch_api_cert()
    setup_api_user(
        pinned_context(API_CERT),
        (admin_env["WAZUH_API_ADMIN_USER"], admin_env["WAZUH_API_ADMIN_PASSWORD"]),
        api_pw,
    )
    setup_indexer_user(
        pinned_context(INDEXER_CA),
        (admin_env["INDEXER_ADMIN_USER"], admin_env["INDEXER_ADMIN_PASSWORD"]),
        idx_pw,
    )

    old_umask = os.umask(0o077)
    try:
        READONLY_ENV.write_text(
            "# Read-only identities for the Wazuh assistant (LAB only).\n"
            "# Generated by lab/scripts/bootstrap_readonly.py — do not commit.\n"
            f"WAZUH_API_URL={API_URL}\n"
            f"WAZUH_API_USER={API_USER}\n"
            f"WAZUH_API_PASSWORD={api_pw}\n"
            f"WAZUH_API_CA={API_CERT}\n"
            f"WAZUH_INDEXER_URL={INDEXER_URL}\n"
            f"WAZUH_INDEXER_USER={INDEXER_USER}\n"
            f"WAZUH_INDEXER_PASSWORD={idx_pw}\n"
            f"WAZUH_INDEXER_CA={INDEXER_CA}\n"
        )
    finally:
        os.umask(old_umask)
    print(f"wrote {READONLY_ENV} (mode 600, passwords not printed)")


if __name__ == "__main__":
    main()
