# Kube Logger

Stream Kubernetes logs from your EKS clusters into a browser viewer with filtering, flow tracing, and per-namespace color coding.

A small local agent holds your AWS credentials and runs `stern`/`kubectl` locally; it forwards log lines through a hosted relay to a web viewer you open in your browser. Your credentials never leave your machine.

```
your laptop                                  logviewer.gtalmor.com
┌──────────────────────────────┐             ┌─────────────────────────────┐
│ kube-logger-agent            │             │ relay + static viewer       │
│ ├─ reads ~/.aws/config       │  wss:// ──► │ ├─ /producer?session=...    │
│ ├─ runs stern/kubectl        │             │ └─ /consumer?session=...    │
│ └─ streams log lines         │             └─────────────────────────────┘
└──────────────────────────────┘                          ▲
                                                          │ (your browser, bookmarked)
                                                          │
                                              https://logviewer.gtalmor.com/?session=...
```

## Install

**macOS / Linux (Homebrew):**

```sh
brew tap gtalmor/kube-logger
brew install kube-logger-agent
```

**Manual download** (if you don't have brew):

```sh
# Pick the asset for your platform from https://github.com/gtalmor/Kube-Logger/releases/latest
curl -LO https://github.com/gtalmor/Kube-Logger/releases/latest/download/kube-logger-agent-darwin-arm64
chmod +x kube-logger-agent-darwin-arm64
./kube-logger-agent-darwin-arm64
```

### Verify integrity

Every release publishes a `SHA256SUMS` file alongside the binaries:

```sh
curl -sL https://github.com/gtalmor/Kube-Logger/releases/latest/download/SHA256SUMS | \
  shasum -a 256 -c --ignore-missing
```

## Use

### 1. Run the agent

```sh
kube-logger-agent
```

On first run it creates `~/.kube-logger/` with a persistent session id and an empty config file, prints your personal viewer URL, and opens it in your default browser. Set `KUBE_LOGGER_NO_BROWSER=1` to suppress the browser launch (e.g. under pm2 / systemd).

```
  Kube Logger Agent on ws://localhost:4040
  Tool: stern | Region: us-east-1 | Clusters configured: 0 — edit /Users/you/.kube-logger/config.json
  Viewer: https://logviewer.gtalmor.com/?session=<your-session-id>

[saas] connecting to wss://logviewer.gtalmor.com/producer?session=<your-session-id>
[saas] connected
```

Leave the agent running in a terminal. Your session id is persistent — the URL stays the same across restarts, so bookmark it once.

### 2. Configure your clusters

Edit `~/.kube-logger/config.json` and map your AWS SSO profiles to the EKS cluster names the agent should point kubeconfig at after login:

```json
{
  "region": "us-east-1",
  "clusters": {
    "my-aws-profile-dev":  "my-eks-cluster-dev",
    "my-aws-profile-prod": "my-eks-cluster-prod"
  },
  "disabledProfiles": []
}
```

Any profile in `disabledProfiles` is hidden from the drawer. Restart the agent after editing.

If you leave `clusters` empty, the agent can still run `aws sso login` on your behalf — you'll just need to run `aws eks update-kubeconfig --name <cluster>` yourself afterwards.

### 3. Open the viewer

Open the URL the agent printed. You should see "Agent connected" in the top bar. Click **⚙ Setup** to:

1. Select an AWS profile and click **Check** (or **SSO Login** if you're not authenticated — a browser window opens on your machine for SSO).
2. Click **Load** to pull the cluster's namespaces.
3. Tick the namespaces you want to capture and click **Start Capture**.

Logs start streaming into the viewer. The filter bar (search, level, pod, request id) and the ⚙ Setup drawer stay available while capturing. You can add/remove namespaces mid-capture.

## Prerequisites

- **AWS CLI v2** with SSO configured (`aws configure sso`).
- **`stern`** (preferred) or `kubectl` on your `PATH`. `brew install stern` on macOS.
- Network access to `logviewer.gtalmor.com` on 443.

## Files the agent uses

| Path | Purpose |
| --- | --- |
| `~/.kube-logger/session` | Persistent session id (32 hex chars). Delete to get a new URL. |
| `~/.kube-logger/config.json` | Profile → cluster map, region, disabled profiles. |
| `~/.aws/config` | Read at startup to discover available SSO profiles. |
| `~/.kube/config` | Updated by `aws eks update-kubeconfig` after SSO login. |

## Troubleshooting

**"Waiting for agent…" in the viewer.** The agent isn't running or can't reach the relay. Check the agent's terminal for a `[saas] connected` line. If you see `[saas] error`, the relay is unreachable — check network/VPN.

**"Clusters configured: 0" at boot.** You haven't populated `~/.kube-logger/config.json` yet. Not fatal — SSO login still works, you'll just need to set kubeconfig yourself.

**"No matches" in the namespace picker after clicking Load.** Either your kubeconfig isn't pointed at the cluster (run `kubectl get namespaces` to sanity-check) or your SSO session expired (check the auth dot next to the profile).

**SSO login opens a browser but the drawer still shows "Not authenticated".** Click **Check** — the agent polls after login but the ticker is conservative.

## Development

The source lives at [gtalmor/Kube-Logger](https://github.com/gtalmor/Kube-Logger). To build binaries locally:

```sh
bun install
bun run build:all      # → dist/kube-logger-agent-{darwin,linux}-{arm64,x64}
```

To release a new version:

```sh
git tag v0.2.0 && git push origin v0.2.0
# The release workflow builds + publishes binaries + SHA256SUMS.
# Then bump version + sha256 in the Homebrew tap:
#   https://github.com/gtalmor/homebrew-kube-logger
```

The relay + hosted viewer are deployed automatically on every push to `main` (see [DEPLOY.md](DEPLOY.md)).
