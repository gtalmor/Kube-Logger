# Kube Logger

Stream Kubernetes logs from your EKS clusters into a browser viewer built for OneWelcome IO (Identity Orchestrator) pods: flow traces, per-node timing waterfalls, slow-node aggregates, request filtering and JSON inspection.

A small local agent holds your AWS credentials and runs `stern` locally; it forwards log lines through a hosted relay to a web viewer. Your credentials never leave your machine.

```
your laptop                                  logviewer.gtalmor.com
┌──────────────────────────────┐             ┌─────────────────────────────┐
│ kube-logger-agent            │             │ relay + static viewer       │
│ ├─ reads ~/.aws/config       │  wss:// ──► │ ├─ /producer?session=…&key=…│
│ ├─ runs stern / aws / kubectl│             │ └─ /consumer?session=…      │
│ └─ streams log-batch frames  │             └─────────────────────────────┘
└──────────────────────────────┘                          ▲
                                                          │ your browser
                                              https://logviewer.gtalmor.com/?session=…
```

## Install

**macOS / Linux (Homebrew):**

```sh
brew tap gtalmor/kube-logger
brew install kube-logger-agent stern
```

**Manual download:**

```sh
# Pick the asset for your platform from https://github.com/gtalmor/Kube-Logger/releases/latest
curl -LO https://github.com/gtalmor/Kube-Logger/releases/latest/download/kube-logger-agent-darwin-arm64
chmod +x kube-logger-agent-darwin-arm64
./kube-logger-agent-darwin-arm64
```

Every release publishes a `SHA256SUMS` file alongside the binaries:

```sh
curl -sL https://github.com/gtalmor/Kube-Logger/releases/latest/download/SHA256SUMS | shasum -a 256 -c --ignore-missing
```

## Use

### 1. Run the agent

```sh
kube-logger-agent
```

On first run it creates `~/.kube-logger/` with a persistent session id, a producer key and an empty config file, prints your personal viewer URL, and opens it in your browser. Set `KUBE_LOGGER_NO_BROWSER=1` to suppress the browser launch (pm2 / systemd).

```
  Kube Logger Agent v0.3.0
  Tool: stern (/opt/homebrew/bin/stern) | Region: us-east-1 | Clusters configured: 2
  Viewer: https://logviewer.gtalmor.com/?session=<your-session-id>

[saas] connecting to wss://logviewer.gtalmor.com/producer?session=<your-session-id>
[saas] connected
```

Leave the agent running. The session id is persistent, so bookmark the URL once. **Treat the URL as a secret**: anyone who has it can drive your agent (start captures, trigger logins). Rotate it with `kube-logger-agent --new-session`.

### 2. Configure your clusters (optional)

Edit `~/.kube-logger/config.json` to map AWS profiles to the EKS cluster the agent should point kubeconfig at after login. If a profile has no mapping, the agent lists the clusters in the region and asks you to pick (or auto-picks when there is exactly one), then remembers the choice.

```json
{
  "region": "us-east-1",
  "clusters": {
    "my-aws-profile-dev":  "my-eks-cluster-dev",
    "my-aws-profile-eu":   { "name": "my-eks-cluster-eu", "region": "eu-west-1" }
  },
  "disabledProfiles": ["noisy-profile"],
  "externalAuthCommands": { "my-saml-profile": "saml2aws login --profile my-saml-profile --skip-prompt" },
  "externalAuthLabels":   { "my-saml-profile": "Keycloak" }
}
```

| Key | Meaning |
| --- | --- |
| `region` | Default region for discovery and `update-kubeconfig`. |
| `clusters` | `profile → "cluster"` or `profile → { name, region }` for clusters outside the default region. |
| `disabledProfiles` | Profiles hidden from the viewer. |
| `externalAuthCommands` | For non-SSO profiles (saml2aws, Keycloak, assume-role helpers): a command the agent runs on **Login** instead of `aws sso login`. It must write credentials for the profile to `~/.aws/credentials`. |
| `externalAuthLabels` / `externalAuthHints` | Button label and fallback hint for such profiles. |

Changes take effect on agent restart.

### 3. Open the viewer

The header shows **Agent connected** when the relay sees your agent. Click **⚙ Setup**:

1. Pick an AWS profile. The agent checks it immediately; click **SSO Login** (or your custom login) if it is expired.
2. Namespaces load automatically once you are authenticated. Tick the ones to capture; expand a namespace to narrow it to specific workloads (live-editable during a capture).
3. **Start capture**. Next time, the welcome screen offers **Resume last capture** with the same selection.

While capturing: search (regex, `/`), **Filters ▾** (levels, services, request ids, hidden patterns, highlights, presets), **View ▾** (follow, wrap, light/dark theme, level colours, buffer size, export, open file). Click a request id for its trace (waterfall, root cause, flow path), `{ }` on a line for the JSON inspector, `n`/`p` to step through errors. The bottom bar shows counts, namespace colours and buffer usage.

The viewer keeps the newest 50k lines in memory by default (configurable in **View ▾**). The agent keeps the newest 20k lines and the relay replays them to a viewer that opens later, so a reload or a reconnect does not lose context.

## Prerequisites

- **AWS CLI v2** with SSO configured (`aws configure sso`), or a credential helper for non-SSO profiles.
- **`stern`** on your `PATH` (`brew install stern`). Required: the agent refuses to capture without it. `KUBE_LOGGER_STERN=/path/to/stern` overrides the lookup.
- **`kubectl`** for namespace and pod listing.
- Network access to `logviewer.gtalmor.com` on 443.

## Agent flags and environment

```
kube-logger-agent --help
```

| Flag / variable | Purpose |
| --- | --- |
| `--open` | Print the viewer URL for the saved session and open it. |
| `--new-session` / `--rotate` | New session id and producer key; the old URL stops working. |
| `--max-log-requests <n>` | Starting (and, when given, maximum) number of concurrent pod streams for stern. Default 100, auto-doubles up to 5000. |
| `KUBE_LOGGER_RELAY` | Relay base URL (default `https://logviewer.gtalmor.com`). Use `http://localhost:4040` for local development. |
| `KUBE_LOGGER_STERN` | Path to stern. |
| `KUBE_LOGGER_NO_SYSTEM_CA=1` | Don't trust the OS certificate store (see Troubleshooting). |
| `KUBE_LOGGER_NO_BROWSER=1` | Don't open the viewer on boot. |
| `KUBE_LOGGER_NO_UPDATE_CHECK=1` | Skip the GitHub release check. |
| `KUBE_LOGGER_FORCE=1` | In non-TTY runs, take over an existing agent instead of refusing. |

## Files the agent uses

| Path | Purpose |
| --- | --- |
| `~/.kube-logger/session` | Persistent session id (in the viewer URL). |
| `~/.kube-logger/producer-key` | Per-machine secret that binds this agent to the session at the relay. Another machine with the same session id but a different key is rejected. |
| `~/.kube-logger/config.json` | Profile → cluster map, region, disabled profiles, external auth commands. |
| `~/.kube-logger/agent.pid` | PID of the live agent. |
| `~/.aws/config`, `~/.aws/credentials` | Read to discover profiles and credential expiry. |
| `~/.kube/config` | Updated by `aws eks update-kubeconfig` after login. |

## Troubleshooting

**"Waiting for agent…"** The agent isn't running or can't reach the relay. Look for `[saas] connected` in its terminal.

**"The relay rejected this agent: another agent owns session …"** The session id is bound to a different producer key (another machine, or a lost `~/.kube-logger/producer-key`). Run `kube-logger-agent --new-session`, or copy the key from the owning machine.

**"TLS handshake failed" / "unable to get local issuer certificate" while browsers work.** A corporate proxy (Zscaler and the like) is re-signing TLS with its own CA. Since 0.3.2 the agent exports the OS-trusted certificates to `~/.kube-logger/ca-bundle.pem` and re-runs itself with `NODE_EXTRA_CA_CERTS` pointing at it, so this should just work; set `KUBE_LOGGER_NO_SYSTEM_CA=1` to disable that, or point `NODE_EXTRA_CA_CERTS` at your own bundle.

**"stern not found"** Install stern or set `KUBE_LOGGER_STERN`. Auth and namespace listing still work without it.

**Namespaces don't load.** Check `kubectl get namespaces` in a terminal: the kubeconfig may point at the wrong cluster or the SSO session may have expired (the auth line in Setup says so).

**Expired login mid-capture.** A banner appears with a **Re-login** button; stern's own auth errors are detected early.

## Development

```sh
npm ci && npm --prefix web ci
npm test                 # agent + relay suites (node:test)
npm run test:web         # viewer unit tests (vitest)

node server/index.js                                     # relay on http://localhost:4040
KUBE_LOGGER_RELAY=http://localhost:4040 node agent/index.js
npm run dev:web                                          # Vite dev server on :5173, proxies /consumer to the relay
```

Open `http://localhost:5173/?session=<id printed by the agent>`; `?demo=1` loads synthetic logs without an agent. `window.__kl.simulate(2000)` streams synthetic lines for performance checks.

Layout: `agent/` (CLI entry + `lib/` pure modules), `server/` (relay + `lib/`), `web/` (Preact + TypeScript viewer; `src/lib` is the pure, tested analysis core), `public/` (legacy viewer, served at `/legacy/` until removed), `test/` (agent + relay tests). Release and deployment: see [DEPLOY.md](DEPLOY.md).
