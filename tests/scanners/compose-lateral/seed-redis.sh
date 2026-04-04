#!/bin/sh
# Wait for Redis to be ready, then seed it with test data.
until redis-cli ping 2>/dev/null | grep -q PONG; do
  sleep 1
done

redis-cli SET "app:db_url" "postgresql://app:ProductionPassword123@db.internal:5432/myapp"
redis-cli SET "app:api_secret" "sk-prod-api-secret-key-never-share-this-value"
redis-cli SET "session:admin" '{"user":"admin","token":"eyJhbGciOiJIUzI1NiJ9.admin","role":"superuser"}'

echo "Redis seeded with test data"
