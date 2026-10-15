--TEST--
swoole_server_port: inherited settings are rejected before server startup
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_ssl();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;

$server = new Server('127.0.0.1', 0, SWOOLE_BASE);
$server->listen('127.0.0.1', 0, SWOOLE_SOCK_TCP | SWOOLE_SSL);
Assert::true($server->set([
    'log_file' => '/dev/null',
    'worker_num' => 1,
    'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
    'ssl_key_file' => SSL_FILE_DIR . '/server.key',
    'ssl_sni_certs' => true,
]));
$server->on('Receive', function () {});
$server->on('WorkerStart', function (Server $server) {
    $server->shutdown();
});
try {
    $server->start();
    Assert::true(false, 'invalid inherited settings must stop startup');
} catch (Swoole\Exception $exception) {
    Assert::contains($exception->getMessage(), 'ssl_sni_certs');
    Assert::same($exception->getCode(), SWOOLE_ERROR_INVALID_PARAMS);
}
echo "DONE\n";
?>
--EXPECT--
DONE
