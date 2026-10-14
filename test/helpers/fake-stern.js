// Stand-in for stern: prints client-go "Watch failed" lines to stderr every
// 100 ms until a file named `healthy` appears next to FAKE_STERN_DIR, then
// streams log lines on stdout instead. Exits on SIGTERM like stern does.
const fs = require('node:fs');
const path = require('node:path');
const ns = process.argv[process.argv.indexOf('-n') + 1] || 'ns';
const flag = path.join(process.env.FAKE_STERN_DIR || '.', 'healthy');
let n = 0;
setInterval(() => {
  if (fs.existsSync(flag)) {
    process.stdout.write(`${ns} pod-1 app 2026-10-14T09:44:0${n % 10}.000Z INFO line ${n++}\n`);
  } else {
    process.stderr.write(`E1014 09:44:06.4390${n++ % 100} ${process.pid} retrywatcher.go:129] "Watch failed" err="Get \\"https://x.gr7.us-east-1.eks.amazonaws.com/api/v1/namespaces/${ns}/pods?watch=true\\": proxyconnect tcp: dial tcp: lookup proxy.dmz.gemaltocloud.com: no such host"\n`);
  }
}, 100);
process.on('SIGTERM', () => process.exit(0));
