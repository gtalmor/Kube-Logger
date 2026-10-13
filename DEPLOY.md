# Kube Logger — Deployment and release

Target: `logviewer.gtalmor.com` → `/var/www/logviewer/` on a Linux box, behind Nginx Proxy Manager, as a pm2 process, deployed by GitHub Actions on every push to `main`.

## Architecture

```
  user laptop                           your Linux box
┌─────────────────────────┐            ┌──────────────────────────────────────────┐
│ kube-logger-agent       │ wss ─────► │ Nginx Proxy Manager (TLS) ─► 127.0.0.1:4040│
│ (stern / aws / kubectl) │            │   server/index.js  (pm2 "logviewer")     │
└─────────────────────────┘            │   - serves web/dist at /  (public/ at /legacy/)
                                       │   - /producer ↔ /consumer per session    │
                                       │   - data/state.json: session→key hashes  │
                                       └──────────────────────────────────────────┘
                                                        ▲ wss /consumer?session=…
                                                 browser: https://logviewer…/?session=…
```

The relay only ever sees log lines in flight (plus a bounded per-session replay buffer). It never has AWS credentials or cluster access.

## Protocol (v2)

- Agent → relay: `init`, `capture-start {captureId}`, `capture-state` (resync, not fanned out), `log-batch {items:[{i,ns,line}]}`, `capture-stop/end`, `cleared`, `stream-end`, `ns-added`, `ns-refiltered`, `stderr`, `error`, `auth-*`, `cluster-pick`, `namespaces`, `pods`.
- Relay → agent: `producer-hello {captureId, lastIndex, lines}` after connect; the agent replays only the lines the relay is missing.
- Relay → viewer: `relay-hello`, `history-begin` … stored `log-batch` frames … `history-end`, then live frames. Viewer actions are forwarded to the agent verbatim; the relay interprets none.
- The first producer on a session binds its key; the binding is persisted (sha256) in `data/state.json` for 90 days of inactivity. A different key gets HTTP 401 (and `GET /producer/check` explains why). Consumers whose socket buffer exceeds 16 MB are closed with code 4002.

## 1. First-time server setup (Ubuntu/Debian)

```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
sudo npm install -g pm2
sudo mkdir -p /var/www/logviewer && sudo chown -R $USER:$USER /var/www/logviewer
```

The server needs no GitHub credential: CI rsyncs the built checkout to it. For the very first start, either push once to `main` (section 2) or copy the repo manually and run:

```bash
cd /var/www/logviewer
npm ci --omit=dev
mkdir -p logs
pm2 start ecosystem.config.js --env production
pm2 save
pm2 startup          # prints a sudo command — run it to survive reboots
curl -s http://127.0.0.1:4040/health   # → ok
```

### Nginx Proxy Manager

Add a Proxy Host: domain `logviewer.gtalmor.com`, scheme `http`, forward `127.0.0.1:4040`, **Websockets support ON**, Block common exploits on, Let's Encrypt cert with Force SSL + HTTP/2.

### Environment (ecosystem.config.js)

| Variable | Default | Meaning |
| --- | --- | --- |
| `HOST` / `PORT` | `127.0.0.1` / `4040` | Bind address. Keep loopback behind NPM. |
| `PUBLIC_DIR` | `web/dist` if built, else `public` | Static root served at `/`. |
| `LEGACY_DIR` | `public` | Served at `/legacy/` while the old viewer is kept. |
| `DATA_DIR` | `./data` | Holds `state.json` (key bindings). Excluded from rsync. |
| `HISTORY_MAX_LINES` / `HISTORY_MAX_BYTES` | 20000 / 10 MB | Per-session replay buffer. |
| `CONSUMER_MAX_BUFFERED_BYTES` | 16 MB | Slow-consumer kick threshold. |

## 2. CI/CD

### Deploy (`.github/workflows/deploy.yml`)

On push to `main`: a `test` job runs `npm test` and the viewer tests; then `deploy` builds `web/` on the runner, rsyncs the checkout (excluding `.git`, `node_modules`, `web/node_modules`, `web/src`, `web/fixtures`, `test`, `logs`, `data`, `.env`) to the server, runs `npm ci --omit=dev` and `pm2 reload logviewer`.

Secrets: `DEPLOY_KEY` (private SSH key whose public half is in the server's `authorized_keys`), `SSH_USER`, `SSH_HOST`, `APP_DIR` (`/var/www/logviewer`).

```bash
ssh-keygen -t ed25519 -f ~/.ssh/logviewer_deploy -N '' -C github-actions-deploy
ssh-copy-id -i ~/.ssh/logviewer_deploy.pub <user>@<server>
ssh <user>@<server> 'bash -lc "which pm2"'     # pm2 must be on PATH in a login shell
```

### Release (`.github/workflows/release.yml`)

Push a tag `vX.Y.Z` (or dispatch with a tag). The `test` job gates a `build` job that stamps the tag into `package.json`, cross-compiles the agent with bun for darwin/linux × arm64/x64, writes `SHA256SUMS`, and creates the GitHub release with generated notes.

A `tap` job then rewrites `Formula/kube-logger-agent.rb` in `gtalmor/homebrew-kube-logger` (version, download URLs, four sha256s) and pushes it. It needs a repository secret **`TAP_TOKEN`**: a fine-grained PAT with *Contents: read and write* on the tap repo. Without the secret the job is skipped and the formula must be bumped by hand.

Cutting a release:

```bash
npm version 0.3.0 --no-git-tag-version      # keep package.json in sync with the tag
git commit -am "chore: release v0.3.0"
git tag v0.3.0 && git push origin main v0.3.0
```

Users then upgrade with `brew update && brew upgrade kube-logger-agent`. The agent prints an upgrade banner when a newer release exists.

## 3. Ops cheatsheet

```bash
pm2 status
pm2 logs logviewer --lines 100
pm2 reload logviewer                 # zero-downtime
curl http://127.0.0.1:4040/health    # liveness
curl http://127.0.0.1:4040/stats     # {"sessions","consumers","bindings","uptime"}
cat /var/www/logviewer/data/state.json | head -c 300   # key bindings (hashed)
```

Removing a binding (e.g. a user lost their producer key and wants to reuse the session id): edit `data/state.json`, delete the session's entry, `pm2 reload logviewer`. Simpler for the user: `kube-logger-agent --new-session`.
