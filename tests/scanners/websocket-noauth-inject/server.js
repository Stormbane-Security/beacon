/**
 * WebSocket server with no authentication and no message validation.
 *
 * Vulnerabilities:
 *   - websocket.no_auth: WebSocket upgrade accepted without any auth
 *   - websocket.message_injection: server echoes back any message without validation
 *   - websocket.cswsh: no Origin header validation
 */
const http = require('http');
const crypto = require('crypto');

const server = http.createServer((req, res) => {
  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
    return;
  }

  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end('<html><body><h1>WebSocket Echo</h1><script>const ws = new WebSocket("ws://"+location.host+"/ws");</script></body></html>');
});

server.on('upgrade', (req, socket, head) => {
  if (req.url !== '/ws') {
    socket.destroy();
    return;
  }

  // No authentication check — websocket.no_auth
  // No Origin validation — websocket.cswsh

  const key = req.headers['sec-websocket-key'];
  if (!key) {
    socket.destroy();
    return;
  }

  const acceptKey = crypto.createHash('sha1')
    .update(key + '258EAFA5-E914-47DA-95CA-5AB5DC11CE56')
    .digest('base64');

  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\n' +
    'Connection: Upgrade\r\n' +
    'Sec-WebSocket-Accept: ' + acceptKey + '\r\n' +
    '\r\n'
  );

  // Echo back any received frames — websocket.message_injection
  socket.on('data', (data) => {
    // Simple echo — no message validation or sanitization
    try { socket.write(data); } catch (e) {}
  });
});

server.listen(3000, '0.0.0.0', () => {
  console.log('WebSocket test server on :3000');
});
