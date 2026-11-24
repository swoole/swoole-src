# Certificates for the SSL examples

The examples do not ship their own certificates. They reuse the test suite's
certificates from `tests/include/ssl_certs/` via `examples/ssl/certs.php`:

    require __DIR__ . '/certs.php';
    $server->set([
        'ssl_cert_file' => SSL_CERT_DIR . 'server.crt',
        'ssl_key_file'  => SSL_CERT_DIR . 'server.key',
    ]);

Useful pairs in that directory: `server.crt` / `server.key`,
`server-cert.pem` / `server-key.pem`, `client.crt` / `client.key`,
`client-cert.pem` / `client-key.pem`, and `ca-cert.pem`.

If you need a fresh self-signed certificate for a local experiment, generate it
outside the repository. Certificate files are never committed here:

    openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
        -keyout /tmp/example.key -out /tmp/example.crt
