/**
 * Vulnerable OAuth provider for drydock testing.
 *
 * Vulnerabilities:
 *   - /authorize accepts any redirect_uri (open redirect)
 *   - /token returns tokens without client_secret validation
 *   - /.well-known/openid-configuration exposes full OAuth metadata
 *   - No HSTS or security headers
 */
const http = require('http');
const url = require('url');

const PORT = 3000;

const OIDC_CONFIG = {
  issuer: 'http://localhost:3000',
  authorization_endpoint: 'http://localhost:3000/authorize',
  token_endpoint: 'http://localhost:3000/token',
  userinfo_endpoint: 'http://localhost:3000/userinfo',
  jwks_uri: 'http://localhost:3000/.well-known/jwks.json',
  response_types_supported: ['code', 'token', 'id_token'],
  grant_types_supported: ['authorization_code', 'implicit', 'client_credentials'],
  subject_types_supported: ['public'],
  id_token_signing_alg_values_supported: ['RS256', 'none'],
  scopes_supported: ['openid', 'profile', 'email'],
};

const JWKS = {
  keys: [
    {
      kty: 'RSA',
      kid: 'test-key-1',
      use: 'sig',
      alg: 'RS256',
      n: 'sXchDaQebHnPiGvhGPEzLSqJzEd2RGGQ2wFHNq5V9H4Vh6r',
      e: 'AQAB',
    },
  ],
};

const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);

  // OIDC discovery
  if (parsed.pathname === '/.well-known/openid-configuration') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(OIDC_CONFIG));
    return;
  }

  // JWKS endpoint
  if (parsed.pathname === '/.well-known/jwks.json') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(JWKS));
    return;
  }

  // Authorization endpoint — accepts ANY redirect_uri (open redirect vuln)
  if (parsed.pathname === '/authorize') {
    const redirectUri = parsed.query.redirect_uri;
    const state = parsed.query.state || '';

    if (!redirectUri) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'missing redirect_uri' }));
      return;
    }

    // Vulnerability: no validation of redirect_uri — blindly redirect
    const sep = redirectUri.includes('?') ? '&' : '?';
    const location = `${redirectUri}${sep}code=auth_code_12345&state=${state}`;
    res.writeHead(302, { Location: location });
    res.end();
    return;
  }

  // Token endpoint — returns tokens without proper validation
  if (parsed.pathname === '/token' && req.method === 'POST') {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
      // Vulnerability: no client_secret check, no code validation
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        access_token: 'eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.',
        token_type: 'bearer',
        expires_in: 604800,
        refresh_token: 'refresh_static_token_never_rotated',
        id_token: 'eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIiwiZW1haWwiOiJhZG1pbkB0ZXN0LmNvbSJ9.',
      }));
    });
    return;
  }

  // Userinfo endpoint
  if (parsed.pathname === '/userinfo') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      sub: '1',
      name: 'Admin User',
      email: 'admin@example.com',
      role: 'administrator',
    }));
    return;
  }

  // Default landing page
  if (parsed.pathname === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<html><body><h1>OAuth Provider</h1></body></html>');
    return;
  }

  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'not found' }));
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`OAuth test server listening on port ${PORT}`);
});
