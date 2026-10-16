// The helper owns only its Vite child; no installed client or account data is used.
const { spawn } = require('node:child_process');
const server = spawn(process.execPath, ['node_modules/vite/bin/vite.js', '--host', '127.0.0.1', '--port', '1420', '--strictPort'], { stdio: 'inherit', windowsHide: true });
async function main() {
  try {
    let ready = false;
    for (let attempt = 0; attempt < 30; attempt++) {
      if (server.exitCode !== null) throw new Error('UI server exited before readiness');
      try { const response = await fetch('http://127.0.0.1:1420', { signal: AbortSignal.timeout(1000) }); if (response.ok) { ready = true; break; } } catch {}
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    if (!ready) throw new Error('UI server did not start');
    const code = await new Promise((resolve, reject) => {
      const test = spawn(process.execPath, ['scripts/ui-smoke.cjs'], { stdio: 'inherit', windowsHide: true, env: { ...process.env, DEVIN_BROWSER_CHANNEL: 'chromium' } });
      test.once('error', reject);
      test.once('exit', code => resolve(code ?? 1));
    });
    process.exitCode = code;
  } finally { server.kill(); }
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
