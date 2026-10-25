# Wazuh LAB (local only)

Official [wazuh-docker](https://github.com/wazuh/wazuh-docker) **single-node v4.14.9**
(pinned commit `56ece955`) plus two `wazuh/wazuh-agent:4.14.9` containers.
Never point anything in this repo at a real/production Wazuh.

```bash
cd lab
./lab.sh setup     # clone upstream (gitignored), generate certs, write admin.env
./lab.sh up        # manager + indexer + dashboard + lab-web-01 + lab-db-01, then stops lab-db-01
./lab.sh users     # create read-only identities -> readonly.env
./lab.sh alerts    # ssh brute force, sudo, FIM, prompt-injection log lines
./lab.sh verify    # curl: reads return 200, every write returns 403
./lab.sh status    # containers + agents (lab-db-01 shows "disconnected")
./lab.sh down      # stop containers (containers + data kept);  ./lab.sh nuke  removes everything
```

## What is in the lab

| Piece | Details |
|---|---|
| Upstream compose | included unmodified via `compose.yaml` → `include:` |
| `compose.lab-override.yml` | publishes only `127.0.0.1:55000` (API), `127.0.0.1:9200` (indexer), `127.0.0.1:443` (dashboard); 1514/1515/514 stay internal |
| `lab-web-01` | active agent; reads `/var/log/lab/auth.log` (syslog), realtime FIM on `/lab/fim`, rootcheck every 5 min with a hidden-file bait in `/dev` |
| `lab-db-01` | enrolled then stopped → `disconnected` agent |
| `config/agent/ossec.conf` | upstream agent config + a marked LAB block |

Alerts produced: sshd 5710/5760 → brute force 5712/5763 (level 10), sudo 5405/5403,
FIM 550/553/554, rootcheck 510, SCA 19003/19007, agent stopped 506.
`./lab.sh alerts injection` writes attacker-controlled text ("ignore all previous
instructions…") into `data.command` / `data.srcuser` of real alerts.

## Read-only identities (`scripts/bootstrap_readonly.py`)

| Identity | Grants | Denied (verified) |
|---|---|---|
| API `assistant_api_ro` → role `assistant_readonly` | `agent/sca/syscheck/rootcheck/syscollector:read` on `agent:id:*`, `rules:read`, `decoders:read`, `mitre:read`, `manager:read`; `allow_run_as=false` | restart/delete agents, active response, create users, restart manager → 403 |
| Indexer `assistant_idx_ro` → role `assistant_alerts_read` | action group `read` on `wazuh-alerts-*`, no cluster permissions | index/delete docs, delete index, other `wazuh-*` indices, `_cat`, creating its own index → 403 |

Lab hardening: the demo `own_index` role mapping (`users: ["*"]`, full access to an
index named like the user) is cleared so the read-only indexer user has no writable index.

## Secrets

`admin.env` (upstream demo admin defaults, read from the upstream compose file),
`readonly.env` (random 32-char passwords) and `certs/` are gitignored, mode 600.
Scripts never print passwords; curl gets them via `-K <(...)`, not argv.
TLS: indexer verified against the lab root CA + hostname (`--resolve wazuh.indexer`);
the API's self-signed cert is pinned by public key (`--pinnedpubkey`).
