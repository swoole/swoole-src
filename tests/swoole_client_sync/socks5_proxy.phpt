--TEST--
swoole_client_sync: http client with http_proxy
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_http_proxy();
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require TESTS_API_PATH . '/swoole_client/http_get.php';

$cli = new Swoole\Client(SWOOLE_TCP);
$cli->set([
    'timeout' => 30,
    'socks5_host' => SOCKS5_PROXY_HOST,
    'socks5_port' => SOCKS5_PROXY_PORT
]);
client_http_v10_get($cli)
?>
--EXPECT--
