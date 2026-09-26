--TEST--
swoole_server_port: set returns false when SSL settings are rejected
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

Assert::false($server->ports[0]->set($settings));
Assert::false($server->set($settings));

echo "DONE\n";
?>
--EXPECTF--
Warning: Swoole\Server\Port::set(): ssl_sni_certs requires an array mapping host names to cert paths in %s on line %d

Warning: Swoole\Server\Port::set(): ssl_sni_certs requires an array mapping host names to cert paths in %s on line %d
DONE
