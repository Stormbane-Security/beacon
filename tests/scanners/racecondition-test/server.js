const http = require('http');

let counter = 0;

const server = http.createServer((req, res) => {
  res.setHeader('Content-Type', 'application/json');

  if (req.method === 'POST' && req.url === '/increment') {
    // No locking, no idempotency key — classic race condition
    const current = counter;
    // Simulate a small delay to widen the race window
    setTimeout(() => {
      counter = current + 1;
      res.writeHead(200);
      res.end(JSON.stringify({ count: counter }));
    }, 5);
    return;
  }

  if (req.method === 'GET' && req.url === '/count') {
    res.writeHead(200);
    res.end(JSON.stringify({ count: counter }));
    return;
  }

  if (req.method === 'GET' && req.url === '/') {
    res.writeHead(200);
    res.end(JSON.stringify({ status: 'ok', endpoints: ['/increment', '/count'] }));
    return;
  }

  res.writeHead(404);
  res.end(JSON.stringify({ error: 'not found' }));
});

server.listen(3000, '0.0.0.0', () => {
  console.log('Race condition test server listening on :3000');
});
