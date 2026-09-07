// Persistent CDP bridge: listens on 127.0.0.1:9222 and forwards to the
// actually-running Chrome DevTools endpoint (read live from DevToolsActivePort).
// This lets the chrome-devtools MCP (configured for 9222) and helper scripts
// always reach the real, logged-in Chrome profile session.
const http = require('http');
const net = require('net');
const fs = require('fs');
const crypto = require('crypto');

const PROFILE = process.env.HOME + '/.config/google-chrome';
const ACTIVE = PROFILE + '/DevToolsActivePort';
const LISTEN_PORT = 9222;

function readActive() {
  try {
    const lines = fs.readFileSync(ACTIVE, 'utf8').split('\n');
    const port = parseInt(lines[0].trim(), 10);
    const wsPath = lines[1].trim();
    return { port, wsPath };
  } catch (e) {
    return null;
  }
}

const server = http.createServer((req, res) => {
  const active = readActive();
  if (req.url === '/json/version') {
    if (!active) { res.writeHead(503); res.end('Chrome not running'); return; }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      Browser: 'Chrome/HeadlessChrome',
      'Protocol-Version': '1.3',
      webSocketDebuggerUrl: `ws://127.0.0.1:${active.port}${active.wsPath}`,
    }));
    return;
  }
  if (req.url === '/json' || req.url === '/json/list' || req.url === '/json/new') {
    // Chrome's HTTP /json API is disabled in this build; synthesize minimal list.
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end('[]');
    return;
  }
  if (!active) { res.writeHead(503); res.end('Chrome not running'); return; }
  const opts = { host: '127.0.0.1', port: active.port, path: req.url, method: req.method, headers: req.headers };
  const p = http.request(opts, (pr) => { res.writeHead(pr.statusCode, pr.headers); pr.pipe(res); });
  p.on('error', () => res.destroy());
  req.pipe(p);
});

server.on('upgrade', (req, clientSocket, head) => {
  const active = readActive();
  if (!active) { clientSocket.destroy(); return; }
  const pSock = net.connect(active.port, '127.0.0.1', () => {
    const key = req.headers['sec-websocket-key'];
    const accept = crypto.createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
    pSock.write([
      'HTTP/1.1 101 Switching Protocols',
      'Upgrade: websocket',
      'Connection: Upgrade',
      'Sec-WebSocket-Accept: ' + accept,
      '\r\n',
    ].join('\r\n'));
    if (head && head.length) pSock.write(head);
    clientSocket.pipe(pSock);
    pSock.pipe(clientSocket);
  });
  pSock.on('error', () => clientSocket.destroy());
  clientSocket.on('error', () => pSock.destroy());
});

server.listen(LISTEN_PORT, '127.0.0.1', () => {
  console.log('[cdp-bridge] listening on 127.0.0.1:' + LISTEN_PORT + ' -> live Chrome DevTools (per ' + ACTIVE + ')');
});
