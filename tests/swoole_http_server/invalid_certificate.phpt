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
try {
    $server->set([
        'ssl_cert_file' => __FILE__,
        'ssl_key_file' => SSL_FILE_DIR . '/server.key',
    ]);
    Assert::true(false, 'invalid certificate must throw');
} catch (Swoole\Exception $exception) {
    Assert::same($exception->getCode(), SWOOLE_ERROR_INVALID_PARAMS);
    Assert::same($exception->getMessage(), 'ssl_init() failed');
}
echo "DONE\n";
?>
--EXPECTF--
[%s]	WARNING	SSLContext::create(): SSL_CTX_use_certificate_file(%s) failed, Error: %s[%d]
[%s]	WARNING	ListenPort::ssl_context_create(): failed to create ssl content
DONE
