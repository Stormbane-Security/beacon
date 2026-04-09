const http = require('http');
const server = http.createServer((req, res) => {
    if (req.url === '/health') { res.writeHead(200); res.end('ok'); return; }
    res.writeHead(404); res.end('Not Found');
});
// Minimal WebSocket upgrade handler
server.on('upgrade', (req, socket, head) => {
    const key = req.headers['sec-websocket-key'];
    const hash = require('crypto').createHash('sha1')
        .update(key + '258EAFA5-E914-47DA-95CA-5AB0DC76B45E').digest('base64');
    socket.write('HTTP/1.1 101 Switching Protocols\r\n' +
        'Upgrade: websocket\r\nConnection: Upgrade\r\n' +
        'Sec-WebSocket-Accept: ' + hash + '\r\n\r\n');
    socket.on('data', (data) => socket.write(data)); // echo
});
server.listen(3000);
