/**
 * JWT server with advanced deep-mode vulnerabilities.
 *
 * Vulnerabilities:
 *   - jwt.algorithm_confusion: accepts HS256-signed tokens using RSA public key as secret
 *   - jwt.audience_missing: accepts tokens with any/missing aud claim
 *   - jwt.issuer_not_validated: accepts tokens from arbitrary issuers
 *   - jwt.no_server_verification: accepts any modified token payload
 *   - jwt.jwks_weak_key: JWKS endpoint has weak 512-bit RSA key
 *   - jwt.jwks_missing_kid: JWKS key has no kid field
 *   - jwt.kid_sql_injection: kid header value used in mock DB lookup (reflected)
 */
const http = require('http');
const crypto = require('crypto');

function base64url(data) {
  return Buffer.from(data).toString('base64url');
}

function makeJWT(header, payload, secret) {
  const h = base64url(JSON.stringify(header));
  const p = base64url(JSON.stringify(payload));
  if (!secret) return h + '.' + p + '.';
  const sig = crypto.createHmac('sha256', secret).update(h + '.' + p).digest('base64url');
  return h + '.' + p + '.' + sig;
}

// Weak 512-bit RSA key for JWKS
const JWKS = {
  keys: [
    {
      kty: 'RSA',
      // No kid field — jwks_missing_kid
      use: 'sig',
      alg: 'RS256',
      // Very short modulus — jwks_weak_key (512-bit)
      n: 'sGkYoWJSZ2WbRP3MMxMoGm4e5GFzFAZZ1ZJt_bSCmQHP6RhFg5j7Y',
      e: 'AQAB',
    },
  ],
};

const SECRET = 'supersecretkey123';

const server = http.createServer((req, res) => {
  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
    return;
  }

  if (req.url === '/.well-known/jwks.json') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(JWKS));
    return;
  }

  if (req.url === '/login') {
    const token = makeJWT(
      { alg: 'HS256', typ: 'JWT' },
      {
        sub: 'admin',
        role: 'superuser',
        iss: 'http://localhost:3000',
        // No aud claim — audience_missing
        iat: Math.floor(Date.now() / 1000),
        exp: 9999999999,
      },
      SECRET
    );
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Set-Cookie': 'session=' + token + '; Path=/',
    });
    res.end(JSON.stringify({ token }));
    return;
  }

  if (req.url === '/api/data') {
    const authHeader = req.headers.authorization || '';
    const cookieHeader = req.headers.cookie || '';
    let token = '';

    if (authHeader.startsWith('Bearer ')) {
      token = authHeader.slice(7);
    } else if (cookieHeader.includes('session=')) {
      token = cookieHeader.split('session=')[1].split(';')[0];
    }

    if (!token) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end('{"error": "No token provided"}');
      return;
    }

    try {
      const parts = token.split('.');
      const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());

      // Vulnerability: no issuer validation — accepts any iss
      // Vulnerability: no audience validation — accepts any/missing aud
      // Vulnerability: no real signature verification — accepts anything
      // Vulnerability: kid SQL injection — kid value logged/echoed
      if (header.kid) {
        // Simulated DB lookup that reflects kid value
        console.log(`Looking up key: SELECT * FROM keys WHERE kid='${header.kid}'`);
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        data: 'secret_data',
        user: payload.sub,
        role: payload.role,
        kid_lookup: header.kid || 'default',
      }));
      return;
    } catch (e) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end('{"error": "Invalid token"}');
      return;
    }
  }

  if (req.url === '/') {
    const token = makeJWT(
      { alg: 'HS256', typ: 'JWT' },
      { sub: 'guest', iat: Math.floor(Date.now() / 1000), exp: 9999999999 },
      SECRET
    );
    res.writeHead(200, {
      'Content-Type': 'text/html',
      'Set-Cookie': 'session=' + token + '; Path=/',
    });
    res.end('<html><body><h1>JWT Advanced App</h1></body></html>');
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not Found');
});

server.listen(3000, '0.0.0.0', () => {
  console.log('JWT advanced test server on :3000');
});
