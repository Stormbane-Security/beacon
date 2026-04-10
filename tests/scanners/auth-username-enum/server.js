/**
 * Login server that leaks username existence via HTTP status codes AND
 * body length differences. The server intentionally varies its response
 * based on whether the email looks like it belongs to a known domain.
 *
 * Vulnerability patterns:
 *   - Known domain emails get a "wrong password" error (401, longer body)
 *   - External domain emails get a "not found" error (404, shorter body)
 *   - Even two unknown users from different domains get different responses
 *
 * This simulates a common vulnerability where the server leaks internal
 * domain membership through differential responses.
 */
const http = require('http');

const server = http.createServer((req, res) => {
  if (req.url === '/health' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
    return;
  }

  // Login page (GET)
  if (req.url === '/login' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<html><body>
<h1>Login</h1>
<form action="/login" method="POST">
  <input type="email" name="email" placeholder="Email" />
  <input type="password" name="password" placeholder="Password" />
  <button type="submit">Sign In</button>
</form>
</body></html>`);
    return;
  }

  // Login endpoint (POST).
  // Vulnerability: every submitted email gets a unique-length response body
  // because the server echoes back a hash of the username in debug data.
  // This causes body-length differences between any two usernames.
  if (req.url === '/login' && req.method === 'POST') {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
      let email = '';
      try {
        const parsed = JSON.parse(body);
        email = parsed.email || parsed.username || '';
      } catch {
        const params = new URLSearchParams(body);
        email = params.get('email') || params.get('username') || '';
      }

      // Generate a variable-length response based on a hash of the email.
      // This simulates a real bug where the server includes user-specific
      // data (lookup result, internal ID, or debug trace) in the error response,
      // causing body-length differences between different usernames.
      let hash = 0;
      for (let i = 0; i < email.length; i++) {
        hash = ((hash << 5) - hash + email.charCodeAt(i)) | 0;
      }
      const padLen = Math.abs(hash % 200) + 50;
      const padding = 'x'.repeat(padLen);

      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: 'Authentication failed',
        request_id: 'req-' + Date.now(),
        trace: padding
      }));
    });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('not found');
});

server.listen(3000, '0.0.0.0', () => {
  console.log('Auth enum test server listening on port 3000');
});
