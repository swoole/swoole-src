--TEST--
swoole_http_client_coro: host
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_constant_not_defined('HTTPBIN_LOCALLY');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $body = json_decode(httpGetBody('http://' . HTTPBIN_SERVER_HOST . ':' . HTTPBIN_SERVER_PORT . '/get'), true);
    Assert::eq((int)(parse_url($body['headers']['Host']))['port'], HTTPBIN_SERVER_PORT);
    echo "DONE\n";
});
?>
--EXPECT--
DONE
