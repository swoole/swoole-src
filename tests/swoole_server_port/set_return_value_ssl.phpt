--TEST--
swoole_server_port: invalid SSL settings throw without merging settings
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_ssl();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;

$server = new Server('127.0.0.1', 0, SWOOLE_BASE, SWOOLE_SOCK_TCP | SWOOLE_SSL);
$settings = [
    'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
    'ssl_key_file' => SSL_FILE_DIR . '/server.key',
    'ssl_sni_certs' => true,
];

foreach ([$server->ports[0], $server] as $target) {
    try {
        $target->set($settings);
        Assert::true(false, 'invalid SNI settings must throw');
    } catch (Swoole\Exception $exception) {
        Assert::contains($exception->getMessage(), 'ssl_sni_certs');
        Assert::same($exception->getCode(), SWOOLE_ERROR_INVALID_PARAMS);
    }
    Assert::null($target->setting);
}
Assert::true($server->set(array_diff_key($settings, ['ssl_sni_certs' => true])));
echo "DONE\n";
?>
--EXPECT--
DONE
