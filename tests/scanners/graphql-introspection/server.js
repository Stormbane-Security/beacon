/**
 * GraphQL server with introspection enabled for drydock testing.
 *
 * Exposes a /graphql endpoint that responds to introspection queries,
 * revealing a schema with sensitive types (User with password_hash,
 * AdminAction with audit trail).
 */
const http = require('http');

const PORT = 3000;

const SCHEMA = {
  queryType: { name: 'Query' },
  mutationType: { name: 'Mutation' },
  types: [
    {
      kind: 'OBJECT',
      name: 'Query',
      fields: [
        { name: 'users', args: [], type: { kind: 'LIST', ofType: { kind: 'OBJECT', name: 'User' } } },
        { name: 'user', args: [{ name: 'id', type: { kind: 'SCALAR', name: 'ID' } }], type: { kind: 'OBJECT', name: 'User' } },
        { name: 'adminActions', args: [], type: { kind: 'LIST', ofType: { kind: 'OBJECT', name: 'AdminAction' } } },
      ],
    },
    {
      kind: 'OBJECT',
      name: 'Mutation',
      fields: [
        { name: 'deleteUser', args: [{ name: 'id', type: { kind: 'SCALAR', name: 'ID' } }], type: { kind: 'OBJECT', name: 'User' } },
      ],
    },
    {
      kind: 'OBJECT',
      name: 'User',
      fields: [
        { name: 'id', type: { kind: 'SCALAR', name: 'ID' } },
        { name: 'name', type: { kind: 'SCALAR', name: 'String' } },
        { name: 'email', type: { kind: 'SCALAR', name: 'String' } },
        { name: 'password_hash', type: { kind: 'SCALAR', name: 'String' } },
        { name: 'role', type: { kind: 'SCALAR', name: 'String' } },
        { name: 'api_key', type: { kind: 'SCALAR', name: 'String' } },
      ],
    },
    {
      kind: 'OBJECT',
      name: 'AdminAction',
      fields: [
        { name: 'id', type: { kind: 'SCALAR', name: 'ID' } },
        { name: 'action', type: { kind: 'SCALAR', name: 'String' } },
        { name: 'actor', type: { kind: 'OBJECT', name: 'User' } },
        { name: 'timestamp', type: { kind: 'SCALAR', name: 'String' } },
      ],
    },
  ],
};

const USERS = [
  { id: '1', name: 'admin', email: 'admin@example.com', password_hash: '$2b$12$fakehashhere', role: 'admin', api_key: 'sk-test-12345' },
  { id: '2', name: 'user', email: 'user@example.com', password_hash: '$2b$12$anotherfake', role: 'user', api_key: 'sk-test-67890' },
];

const server = http.createServer((req, res) => {
  // Health check
  if (req.url === '/health' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
    return;
  }

  // Landing page
  if (req.url === '/' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<html><body><h1>GraphQL API</h1><p>POST /graphql</p></body></html>');
    return;
  }

  // GraphQL endpoint — accepts both GET and POST
  if (req.url === '/graphql' || req.url.startsWith('/graphql?')) {
    if (req.method === 'GET') {
      // GET with query parameter
      const url = new URL(req.url, `http://${req.headers.host}`);
      const query = url.searchParams.get('query') || '';
      handleGraphQL(query, res);
      return;
    }

    if (req.method === 'POST') {
      let body = '';
      req.on('data', (chunk) => { body += chunk; });
      req.on('end', () => {
        try {
          const parsed = JSON.parse(body);
          // Support batch queries (array of operations)
          if (Array.isArray(parsed)) {
            const results = parsed.map(op => {
              const q = (op && op.query) || '';
              return handleGraphQLSync(q);
            });
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(results));
            return;
          }
          handleGraphQL(parsed.query || '', res);
        } catch {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ errors: [{ message: 'Invalid JSON' }] }));
        }
      });
      return;
    }
  }

  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'not found' }));
});

function handleGraphQLSync(query) {
  if (query.includes('__schema') || query.includes('__type')) {
    return { data: { __schema: SCHEMA } };
  } else if (query.includes('users')) {
    return { data: { users: USERS } };
  } else {
    return { data: null, errors: [{ message: 'Unknown query' }] };
  }
}

function handleGraphQL(query, res) {
  const result = handleGraphQLSync(query);
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(result));
}

server.listen(PORT, '0.0.0.0', () => {
  console.log(`GraphQL test server listening on port ${PORT}`);
});
