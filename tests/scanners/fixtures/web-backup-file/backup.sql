-- MySQL dump
INSERT INTO users (id, username, password_hash) VALUES (1, 'admin', '$2b$12$abc123');
INSERT INTO users (id, username, password_hash) VALUES (2, 'user', '$2b$12$def456');
INSERT INTO sessions (id, token) VALUES (1, 'eyJhbGciOiJIUzI1NiJ9.test');
