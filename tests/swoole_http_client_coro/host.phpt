--TEST--
swoole_http_client_coro: host
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
require __DIR__ . '/../include/config.php';
skip('HTTPBIN_SERVER_PORT can not be 80', HTTPBIN_SERVER_PORT === 80);
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $body = json_decode(httpGetBody('http://' . HTTPBIN_SERVER_HOST . ':' . HTTPBIN_SERVER_PORT . '/get'), true);
    Assert::same((int)(parse_url($body['headers']['Host']))['port'], HTTPBIN_SERVER_PORT);
    echo "DONE\n";
});
?>
--EXPECT--
DONE
