// Reusable CDP helper for the live Chrome profile.
// Usage:
//   node cdp.js open <url>          # open a new tab in the existing browser
//   node cdp.js list                # list open tabs/targets
//   node cdp.js close <targetId>    # close a tab
//   node cdp.js navigate <targetId> <url>
const fs = require('fs');
const HOME = process.env.HOME;

function readWs() {
  const lines = fs.readFileSync(HOME + '/.config/google-chrome/DevToolsActivePort', 'utf8').split('\n');
  return 'ws://127.0.0.1:' + parseInt(lines[0].trim(), 10) + lines[1].trim();
}

function connect() {
  const ws = new WebSocket(readWs());
  const pending = new Map();
  let msgId = 1;
  ws.addEventListener('open', () => flush());
  ws.addEventListener('error', (e) => { console.error('WS error', e.message || e); process.exit(1); });
  const queue = [];
  function flush() {}
  ws._send = (method, params) => new Promise((resolve, reject) => {
    const id = msgId++;
    pending.set(id, { resolve, reject });
    ws.send(JSON.stringify({ id, method, params: params || {} }));
  });
  ws.addEventListener('message', (ev) => {
    const m = JSON.parse(typeof ev.data === 'string' ? ev.data : ev.data.toString());
    if (m.id && pending.has(m.id)) {
      const p = pending.get(m.id); pending.delete(m.id);
      if (m.error) p.reject(new Error(JSON.stringify(m.error))); else p.resolve(m.result);
    }
  });
  return new Promise((resolve) => ws.addEventListener('open', () => resolve(ws)));
}

async function main() {
  const cmd = process.argv[2];
  const ws = await connect();
  if (cmd === 'open') {
    const url = process.argv[3] || 'about:blank';
    const r = await ws._send('Target.createTarget', { url, newWindow: true });
    console.log('opened ' + r.targetId + ' -> ' + url);
  } else if (cmd === 'list') {
    const r = await ws._send('Target.getTargets');
    for (const t of r.targetInfos) {
      if (t.type === 'page') console.log(t.targetId + '\t' + (t.url || '') + '\t' + (t.title || ''));
    }
  } else if (cmd === 'close') {
    const id = process.argv[3];
    await ws._send('Target.closeTarget', { targetId: id });
    console.log('closed ' + id);
  } else if (cmd === 'navigate') {
    const id = process.argv[3]; const url = process.argv[4];
    await ws._send('Target.activateTarget', { targetId: id });
    await ws._send('Page.navigate', { url }, );
    console.log('navigated ' + id + ' -> ' + url);
  } else {
    console.log('Usage: node cdp.js [open <url>|list|close <targetId>|navigate <targetId> <url>]');
  }
  ws.close();
  process.exit(0);
}
main().catch((e) => { console.error(e.message); process.exit(1); });
