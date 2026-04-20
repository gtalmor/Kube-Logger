// pm2 process manifest for the Kube Logger SaaS relay.
//
// Deploy usage on the Linux box (after `npm ci --omit=dev`):
//   pm2 start ecosystem.config.js --env production
//   pm2 save                        # persist across reboots (with pm2-startup)
//
// Reload on git pull (zero-downtime):
//   pm2 reload logviewer
module.exports = {
  apps: [
    {
      name: 'logviewer',
      script: 'server/index.js',
      instances: 1,
      exec_mode: 'fork',            // single process — the relay holds in-memory sessions
      watch: false,                 // CI/CD handles restarts; don't auto-reload on fs change
      max_memory_restart: '256M',
      env: {
        NODE_ENV: 'production',
        // Listen only on loopback; NPM (Nginx Proxy Manager) terminates TLS in front
        HOST: '127.0.0.1',
        PORT: '4040',
      },
      out_file: './logs/out.log',
      error_file: './logs/err.log',
      merge_logs: true,
      time: true,
    },
  ],
};
