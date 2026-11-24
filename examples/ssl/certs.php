<?php
// Certificates are shared with the test suite; examples/ keeps no copies.
// Include this file and build paths with SSL_CERT_DIR, for example:
//   'ssl_cert_file' => SSL_CERT_DIR . 'server.crt',
//   'ssl_key_file'  => SSL_CERT_DIR . 'server.key',
if (!defined('SSL_CERT_DIR')) {
    define('SSL_CERT_DIR', dirname(__DIR__, 2) . '/tests/include/ssl_certs/');
}
