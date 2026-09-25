--TEST--
swoole_http_server: reject an invalid default certificate
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_ssl();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Http\Server;

$server = new Server('127.0.0.1', get_one_free_port(), SWOOLE_BASE, SWOOLE_SOCK_TCP | SWOOLE_SSL);
$server->set([
    'ssl_cert_file' => __FILE__,
    'ssl_key_file' => SSL_FILE_DIR . '/server.key',
]);
echo "UNEXPECTED\n";
?>
--EXPECTF--
[%s]	WARNING	SSLContext::create(): SSL_CTX_use_certificate_file(%s) failed, Error: %s[%d]
[%s]	WARNING	ListenPort::ssl_context_create(): failed to create ssl content

Fatal error: Swoole\Server\Port::set(): ssl_init() failed in %s on line %d
