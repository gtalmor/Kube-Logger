# Kube Logger — SaaS Deployment

Target: `logviewer.gtalmor.com` → `/var/www/logviewer/` on a Linux box, behind Nginx Proxy Manager, pm2 process, deployed from GitHub on every push to `main`.

## Architecture at a glance

```
user laptop                                your Linux box
┌──────────────────────────┐               ┌─────────────────────────────────┐
│ Chrome extension (popup) │  ws://local   │                                 │
│          │               │◄─────────────►│  agent/index.js   (local only)  │  ← runs on USER's laptop
│          ▼               │               │  (not deployed on server!)      │
│ agent (runs on laptop)   │               └─────────────────────────────────┘
│          │ wss://logviewer.gtalmor.com/producer?session=ABC
│          ▼
└──────────┼───────────────┘
           │
           ▼
  ┌────────────────────────────────────────────────────────────────────────┐
  │                    your Linux box (this repo deployed here)            │
  │                                                                         │
  │ Nginx Proxy Manager  ─ TLS terminates ─►  127.0.0.1:4040               │
  │                                              │                          │
  │                                              ▼                          │
  │                                   server/index.js (pm2 "logviewer")    │
  │                                   - serves public/index.html           │
  │                                   - routes /producer ↔ /consumer       │
  └────────────────────────────────────────────────────────────────────────┘
                                                  ▲
                                                  │ wss://logviewer.gtalmor.com/consumer?session=ABC
                                                  │
                                     ┌────────────┴────────────┐
                                     │ Browser tab (any laptop)│
                                     │ https://logviewer…/?s=ABC│
                                     └─────────────────────────┘
```

The **server only knows about log lines in flight**. It never has AWS credentials or kubectl access. Every user still runs `agent/index.js` locally with their own AWS SSO login.

---

## 1. First-time server setup

Assumes Ubuntu/Debian. Adjust for your distro.

### 1a. Install prerequisites

```bash
# Node 20 (LTS) + git
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs git
sudo npm install -g pm2

# Verify
node -v && npm -v && pm2 --version
```

### 1b. Create the app directory

```bash
sudo mkdir -p /var/www/logviewer
sudo chown -R $USER:$USER /var/www/logviewer
```

### 1c. Authenticate to GitHub (private repo)

Install the GitHub CLI and log in once; it wires up git's credential helper so
every subsequent `git fetch`/`git pull` on the box just works.

```bash
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
  | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
  | sudo tee /etc/apt/sources.list.d/github-cli.list
sudo apt update && sudo apt install -y gh

# Interactive: pick GitHub.com → HTTPS → "Login with a web browser" → enter the
# one-time code it prints at https://github.com/login/device.
gh auth login
gh auth setup-git
```

Verify: `gh auth status` should show you logged in.

> Note: `gh auth login` authenticates as **you** (your whole GitHub account).
> For a shared or long-lived server you'd prefer a read-only per-repo **Deploy
> key** instead; see the `Option A` section in the original conversation or
> swap in whenever you're ready.

### 1d. Clone and install

```bash
cd /var/www/logviewer
git clone https://github.com/<your-org>/<your-repo>.git .

npm ci --omit=dev
mkdir -p logs
```

### 1e. Start with pm2

```bash
pm2 start ecosystem.config.js --env production
pm2 save
pm2 startup          # prints a sudo command — run it to make pm2 survive reboots
```

Check it's alive:

```bash
curl -s http://127.0.0.1:4040/health  # → "ok"
pm2 logs logviewer --lines 30
```

### 1f. Put it behind Nginx Proxy Manager

In NPM's UI, add a new Proxy Host:

- **Domain:** `logviewer.gtalmor.com`
- **Scheme:** `http`
- **Forward hostname / IP:** `127.0.0.1`
- **Forward port:** `4040`
- **Cache assets:** off
- **Block common exploits:** on
- **Websockets support:** **ON** (critical — without this `/producer` and `/consumer` won't upgrade)
- **SSL tab:** request a Let's Encrypt cert for the domain, force SSL, HTTP/2 on.

Point your DNS `logviewer.gtalmor.com` → the box's public IP, wait for propagation, then NPM can issue the cert.

### 1f. Smoke-test the relay

From any machine:

```bash
curl https://logviewer.gtalmor.com/health   # → "ok"
```

Open `https://logviewer.gtalmor.com/` in a browser — you should see the viewer UI with "No session — add ?s=<id> to the URL" in the status bar. That's expected; the viewer only activates once a session id is in the query string.

---

## 2. GitHub CI/CD (auto-deploy on push to `main`)

### 2a. Create a deploy SSH key (on your laptop, **not** the server)

```bash
ssh-keygen -t ed25519 -f ~/.ssh/logviewer_deploy -N '' -C 'github-actions-deploy'
```

### 2b. Add the public key to the server

```bash
# Copy ~/.ssh/logviewer_deploy.pub into the server's authorized_keys
ssh-copy-id -i ~/.ssh/logviewer_deploy.pub <user>@<server-ip>
# Or paste it manually into ~/.ssh/authorized_keys on the server.
```

Test: `ssh -i ~/.ssh/logviewer_deploy <user>@<server-ip> 'echo ok'` should print `ok`.

### 2c. Add GitHub repository secrets

In your repo: **Settings → Secrets and variables → Actions → New repository secret**.

| Name         | Value                                             |
| ------------ | ------------------------------------------------- |
| `DEPLOY_KEY` | Contents of `~/.ssh/logviewer_deploy` (the **private** key, full file) |
| `SSH_USER`   | The Linux user that owns `/var/www/logviewer/`     |
| `SSH_HOST`   | The server's hostname or IP                        |
| `APP_DIR`    | `/var/www/logviewer`                               |

### 2d. Ensure pm2 works in non-interactive shells

The deploy workflow SSHes in and runs `pm2` under bash. pm2 needs to be on PATH in a login shell. Check:

```bash
ssh <user>@<server> 'bash -lc "which pm2"'
```

If nothing prints, add `export PATH="$PATH:$(npm prefix -g)/bin"` to `~/.profile` on the server.

### 2e. Push and verify

Push any change to `main`. Actions tab → you should see the `Deploy SaaS relay` workflow run; it ssh's in, pulls, installs, and reloads pm2. `pm2 describe logviewer` should show a new `restart_time`.

---

## 3. How users consume the SaaS

Each user on their own laptop:

1. Install the Chrome extension (loaded unpacked from the `extension/` folder, or published to the Chrome Web Store).
2. Run the local agent somewhere:
   ```bash
   git clone <repo>
   cd <repo>
   npm ci
   npm run start:agent
   ```
   (Requires `aws` CLI, `stern`, and `kubectl` on their `$PATH`. AWS SSO login is handled via the popup as before.)
3. Open the popup → `Relay` opens a small config — default `https://logviewer.gtalmor.com` is already set.
4. Pick a profile, authenticate, pick namespace(s), click **Start Capture**.
5. The popup generates a random 128-bit session id, tells the local agent to open an outbound `wss://logviewer.gtalmor.com/producer?session=…`, and opens the web viewer at `https://logviewer.gtalmor.com/?s=…` in a new tab.
6. Logs stream from the user's laptop → through the relay → into the viewer tab. Multiple viewers can open the same session URL.

No AWS credentials ever leave the user's laptop. The relay only sees log lines.

---

## 4. Ops cheatsheet

```bash
pm2 status                          # running processes
pm2 logs logviewer --lines 100      # tail logs
pm2 restart logviewer               # hard restart
pm2 reload logviewer                # zero-downtime reload
pm2 describe logviewer              # details + restart count

curl http://127.0.0.1:4040/health   # liveness
curl http://127.0.0.1:4040/stats    # active session count, uptime
```

If a deploy gets stuck, `ssh` to the box and:

```bash
cd /var/www/logviewer
git status
git log -1 --oneline
pm2 logs logviewer --err --lines 50
```
