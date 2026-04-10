const http = require('http');

http.createServer((req, res) => {
    const origin = req.headers.origin || '*';

    // Dangerous: reflect any origin AND allow credentials
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');

    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
    }

    if (req.url === '/health') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('ok');
        return;
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end('{"secret": "data", "api_key": "sk-1234567890"}');
}).listen(3000);
