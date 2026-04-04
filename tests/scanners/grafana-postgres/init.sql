CREATE TABLE IF NOT EXISTS customers (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(200) NOT NULL,
    ssn VARCHAR(11) NOT NULL,
    credit_card VARCHAR(19) NOT NULL
);

INSERT INTO customers (name, email, ssn, credit_card) VALUES
    ('John Doe', 'john@example.com', '123-45-6789', '4111-1111-1111-1111'),
    ('Jane Smith', 'jane@example.com', '987-65-4321', '5500-0000-0000-0004'),
    ('Bob Wilson', 'bob@example.com', '456-78-9012', '3400-0000-0000-009'),
    ('Alice Brown', 'alice@example.com', '234-56-7890', '6011-0000-0000-0004'),
    ('Charlie Davis', 'charlie@example.com', '345-67-8901', '3530-1113-3330-0000');

-- Service credentials stored in the database (realistic scenario)
CREATE TABLE IF NOT EXISTS service_credentials (
    id SERIAL PRIMARY KEY,
    service_name VARCHAR(100) NOT NULL,
    username VARCHAR(100) NOT NULL,
    password VARCHAR(200) NOT NULL,
    endpoint VARCHAR(500) NOT NULL
);

INSERT INTO service_credentials (service_name, username, password, endpoint) VALUES
    ('internal-api', 'api_admin', 'SuperSecretAPIKey123!', 'http://internal-api:8080'),
    ('redis-cache', '', 'redis_auth_token_xyz', 'redis://redis:6379'),
    ('s3-backup', 'AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', 's3://customer-backups');
