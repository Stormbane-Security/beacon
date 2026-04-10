/**
 * Vulnerable SAML Service Provider mock for drydock testing.
 *
 * Exposes:
 * - /saml/metadata   — SAML SP metadata (EntityDescriptor)
 * - /saml/sso        — SSO endpoint that redirects (SAML endpoint_exposed)
 * - /saml/acs        — Assertion Consumer Service (accepts POST)
 * - /health          — health check
 *
 * Vulnerabilities (for beacon deep-mode detection):
 * - saml.signature_not_validated: accepts assertions without verifying XML signatures
 * - saml.issuer_not_validated: accepts assertions from any issuer
 * - saml.xxe_injection: XML parser processes external entities
 * - saml.xml_signature_wrapping: does not detect signature wrapping attacks
 * - saml.open_redirect: RelayState parameter used as redirect target without validation
 */
const http = require('http');

const PORT = 3000;

const METADATA = `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="http://localhost:${PORT}/saml/metadata"
    validUntil="2028-01-01T00:00:00Z">
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
      AuthnRequestsSigned="false" WantAssertionsSigned="false">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>MIICpDCCAYwCCQC3Y22fHAT3TDANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAl0ZXN0LXNhbWwwHhcNMjQwMTAxMDAwMDAwWhcNMjgwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAl0ZXN0LXNhbWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7o5e7Uf94ELf5FsSJLcykBHgMdQB9JN3v5fLJp5x5p7dMo6XQQ5fFIg3mNLhK5sFa1l6p0X3I3N5K7k0BHwA5TN7K8X3L9F2y3h7D8w4Z5p0X3A9K2y5h7B8c4W5n0V3G9J2x5g7E8b4U5m0T3F9I2w5f7D8a4S5l0R3E9H2v5e7C8Z4Q5k0P3D9G2u5d7B8Y4O5j0N3C9F2t5c7A8X4M5i0L3B9E2s5b6Z8W4K5h0J3A9D2r5a6Y8V4I5g0H3z9C2q5Z6X8U4G5f0F3y9B2p5Y6W8T4E5e0D3x9A2o5X6V8S4C5d0B3w8Z2n5W6U8R4A5c0z3v8Y2m5V6T8Q3z5b0y3u8X2l5U6S8P3y5a0x3t8W2k5T6R8O3x5Z0w3s8V2j5S6Q8N3w5Y0v3r8U2i5R6P8M3v5X0u3q8T2h5Q6O8L3u5W0t3p8S2g5P6N8K3t5V0s3o8R2f5O6M8J3s5U0r3n8Q2e5N6L8I3r5T0q3m8P2d5M6K8H3q5S0p3l8O2c5L6J8G3p5R0o3k8N2b5K6I8F3o5Q0n3j8M2a5J6H8E3n5P0m3i8L1z5I6G8D3m5O0l3h8K1y5H6F8C3l5N0k3g8J1x5G6E8B3k5M0j3f8I1w5F6D8A3j5L0i3e8H1v5E6C7z3i5K0h3d8G1u5D6B7y3h5J0g3c8F1t5C6A7x3g5I0f3b8E1s5B5z7w3f5H0e3a8D1r5A5y7v3e5G0d2z8C1q4z5x7u3d5F0c2y8B1p4y5w7t3c5E0b2x8A1o4x5v7s3b5D0a2w7z1n4w5u7r3a5C</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="http://localhost:${PORT}/saml/slo"/>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="http://localhost:${PORT}/saml/acs" index="0" isDefault="true"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>`;

const server = http.createServer((req, res) => {
  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
    return;
  }

  if (req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<html><body><h1>SAML SP</h1><a href="/saml/sso">Login via SAML</a></body></html>');
    return;
  }

  // SAML metadata endpoint
  if (req.url === '/saml/metadata' || req.url === '/saml/metadata/') {
    res.writeHead(200, { 'Content-Type': 'application/xml' });
    res.end(METADATA);
    return;
  }

  // SAML SSO endpoint — accepts GET redirect binding
  if (req.url.startsWith('/saml/sso')) {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<html><body><h1>SAML SSO</h1><p>IdP would redirect here</p></body></html>');
    return;
  }

  // SAML ACS endpoint — VULNERABLE: accepts any POST without signature validation
  if (req.url === '/saml/acs' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      // Check for RelayState — open redirect vulnerability
      const params = new URLSearchParams(body);
      const relayState = params.get('RelayState') || '';

      if (relayState && (relayState.startsWith('http://') || relayState.startsWith('https://'))) {
        // VULNERABLE: redirect to RelayState without validation (saml.open_redirect)
        res.writeHead(302, { 'Location': relayState });
        res.end();
        return;
      }

      const samlResponse = params.get('SAMLResponse') || '';

      if (!samlResponse) {
        res.writeHead(400, { 'Content-Type': 'text/plain' });
        res.end('Missing SAMLResponse');
        return;
      }

      // VULNERABLE: decode and "process" without signature validation
      try {
        const decoded = Buffer.from(samlResponse, 'base64').toString('utf-8');

        // VULNERABLE: no signature check (saml.signature_not_validated)
        // VULNERABLE: no issuer validation (saml.issuer_not_validated)
        // Accept any assertion that contains <Assertion>
        if (decoded.includes('Assertion') || decoded.includes('Response')) {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end('<html><body><h1>Authenticated</h1><p>Welcome, user</p></body></html>');
          return;
        }
      } catch (e) {
        // fall through
      }

      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<html><body><h1>Authenticated</h1><p>SAML login accepted</p></body></html>');
    });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not Found');
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`SAML vulnerable SP listening on port ${PORT}`);
});
