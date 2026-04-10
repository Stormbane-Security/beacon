const http = require('http');
const crypto = require('crypto');

function base64url(data) {
    return Buffer.from(data).toString('base64url');
}

function makeJWT(header, payload) {
    const h = base64url(JSON.stringify(header));
    const p = base64url(JSON.stringify(payload));
    return h + '.' + p + '.';
}

const SECRET = 'supersecretkey123';

http.createServer((req, res) => {
    if (req.url === '/health') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('ok');
        return;
    }

    // JWKS endpoint with a deliberately weak 1024-bit RSA key (for jwt.jwks_weak_key)
    // and no kid field (for jwt.jwks_missing_kid). Also enables jwt.algorithm_confusion
    // since the scanner can read the public key and forge an HS256 token with it.
    if (req.url === '/.well-known/jwks.json' || req.url === '/jwks.json') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            keys: [{
                kty: 'RSA',
                // 1024-bit RSA modulus (weak — below 2048-bit minimum)
                n: 'vrjOfz9Ccdg6QBe_DGBvJuoY-Hf_w7WsCQUJSvz7m9P9xUuoPUxBt4sPSHZKHMBUa0PKHxXLQCAuEG6WRxnHK9x_mVqiYG2IvQ7GTB_RjI91ZIz7oFTZLY_eNHuWqS0v',
                e: 'AQAB',
                alg: 'RS256',
                use: 'sig'
                // NOTE: deliberately no kid field
            }]
        }));
        return;
    }

    if (req.url === '/login') {
        // Issue a JWT with alg:none (vulnerability)
        const token = makeJWT(
            { alg: 'none', typ: 'JWT' },
            {
                sub: 'admin',
                role: 'superuser',
                email: 'admin@internal.corp',
                iat: Math.floor(Date.now() / 1000),
                exp: 9999999999,
            }
        );
        res.writeHead(200, {
            'Content-Type': 'application/json',
            'Set-Cookie': 'session=' + token + '; Path=/; HttpOnly',
        });
        res.end(JSON.stringify({ token: token }));
        return;
    }

    // VULNERABLE: Accept tokens at multiple API paths (the JWT scanner probes
    // /api/v1/users, /api/me, /profile, /api/user, /me, and /api/data).
    const protectedPaths = ['/api/data', '/api/v1/users', '/api/me', '/profile', '/api/user', '/me'];
    if (protectedPaths.includes(req.url)) {
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

        // VULNERABLE: Accept tokens with multiple bypass techniques
        try {
            const parts = token.split('.');
            const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
            const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());

            // Vuln 1: Accept alg:none case variants without verification
            if (header.alg === 'none' || header.alg === 'None' || header.alg === 'NONE' || header.alg === 'nOnE') {
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ data: 'secret', user: payload.sub }));
                return;
            }

            // Vuln 2: Accept HS256 with empty secret (misconfigured JWT_SECRET)
            if (header.alg === 'HS256') {
                // Accept any HS256 token — simulates empty/weak secret
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ data: 'secret', user: payload.sub }));
                return;
            }

            // Vuln 3: kid SQL injection — accept tokens with kid containing SQL
            if (header.kid && (header.kid.includes("'") || header.kid.includes("--"))) {
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ data: 'secret', user: payload.sub }));
                return;
            }
        } catch (e) {
            // fall through
        }

        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end('{"error": "Invalid token"}');
        return;
    }

    // Root path: serve a page with a JWT in a cookie
    if (req.url === '/') {
        const token = makeJWT(
            { alg: 'none', typ: 'JWT' },
            { sub: 'guest', role: 'viewer', iat: Math.floor(Date.now() / 1000), exp: 9999999999 }
        );
        res.writeHead(200, {
            'Content-Type': 'text/html',
            'Set-Cookie': 'session=' + token + '; Path=/; HttpOnly',
        });
        res.end('<html><body><h1>JWT App</h1></body></html>');
        return;
    }

    // Unknown paths: 404 (prevents catch-all false positive detection)
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found');
}).listen(3000);
