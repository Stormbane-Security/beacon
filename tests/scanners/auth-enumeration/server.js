/**
 * Login form with username enumeration and no lockout.
 *
 * Vulnerabilities:
 *   - Different error messages for valid vs invalid usernames
 *   - No account lockout after repeated failed attempts
 *   - No rate limiting
 */
const http = require('http');

const VALID_USERS = { admin: 'secretpass', user: 'password123' };

const server = http.createServer((req, res) => {
  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
    return;
  }

  if (req.url === '/' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<html><body>
<h1>Login</h1>
<form method="POST" action="/login">
  <input type="text" name="username" placeholder="Username" />
  <input type="password" name="password" placeholder="Password" />
  <button type="submit">Login</button>
</form>
</body></html>`);
    return;
  }

  if (req.url === '/login' && req.method === 'POST') {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
      const params = new URLSearchParams(body);
      const username = params.get('username') || '';
      const password = params.get('password') || '';

      // Vulnerability: different responses for valid vs invalid users
      if (!(username in VALID_USERS)) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'User not found' }));
        return;
      }

      if (VALID_USERS[username] !== password) {
        // Vulnerability: reveals user exists but password is wrong
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid password for this account' }));
        return;
      }

      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Set-Cookie': 'session=authenticated; Path=/',
      });
      res.end(JSON.stringify({ message: 'Login successful', user: username }));
    });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not Found');
});

server.listen(3000, '0.0.0.0', () => {
  console.log('Auth test server on :3000');
});
