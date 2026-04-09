/**
 * API server with no rate limiting and missing Retry-After header.
 *
 * Vulnerabilities:
 *   - api.rate_limit_missing: no rate limit on any endpoint
 *   - api.rate_limit_no_retry_after: no Retry-After header
 *   - api.bola: different user IDs return different user data without auth
 *   - api.mass_assignment: extra fields accepted on user creation
 */
const http = require('http');

const USERS = {
  '1': { id: '1', name: 'Alice', email: 'alice@example.com', role: 'admin' },
  '2': { id: '2', name: 'Bob', email: 'bob@example.com', role: 'user' },
};

const server = http.createServer((req, res) => {
  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
    return;
  }

  if (req.url === '/' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<html><body><h1>API Server</h1><p>GET /api/users/:id</p></body></html>');
    return;
  }

  // BOLA: any user ID accessible without authorization check
  const userMatch = req.url.match(/^\/api\/users\/(\d+)$/);
  if (userMatch && req.method === 'GET') {
    const user = USERS[userMatch[1]];
    if (user) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(user));
    } else {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'User not found' }));
    }
    return;
  }

  // Mass assignment: accepts any fields in POST body
  if (req.url === '/api/users' && req.method === 'POST') {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
      try {
        const data = JSON.parse(body);
        // Vulnerability: blindly assigns all fields including role
        const newUser = { id: '3', ...data };
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(newUser));
      } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid JSON' }));
      }
    });
    return;
  }

  // API fuzz endpoint — returns 500 on unexpected input
  if (req.url === '/api/process' && req.method === 'POST') {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
      try {
        const data = JSON.parse(body);
        if (!data.input || typeof data.input !== 'string') {
          throw new Error('Invalid input');
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ result: data.input.toUpperCase() }));
      } catch (e) {
        // Vulnerability: stack trace in 500 response
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          error: 'Internal Server Error',
          message: e.message,
          stack: e.stack,
        }));
      }
    });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'not found' }));
});

server.listen(3000, '0.0.0.0', () => {
  console.log('API test server on :3000');
});
