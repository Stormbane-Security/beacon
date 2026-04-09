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

        // VULNERABLE: Accept alg:none tokens without verification
        try {
            const parts = token.split('.');
            const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
            const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());

            if (header.alg === 'none' || header.alg === 'None' || header.alg === 'NONE' || header.alg === 'nOnE') {
                // Accept without verification — vulnerability!
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

    // Default: serve a page with a JWT in a cookie
    const token = makeJWT(
        { alg: 'none', typ: 'JWT' },
        { sub: 'guest', role: 'viewer', iat: Math.floor(Date.now() / 1000), exp: 9999999999 }
    );
    res.writeHead(200, {
        'Content-Type': 'text/html',
        'Set-Cookie': 'session=' + token + '; Path=/; HttpOnly',
    });
    res.end('<html><body><h1>JWT App</h1></body></html>');
}).listen(3000);
