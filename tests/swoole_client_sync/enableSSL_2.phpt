--TEST--
swoole_client_async: enableSSL
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$cli = new Swoole\Client(SWOOLE_SOCK_TCP);
Assert::true($cli->connect("www.baidu.com", 443, 2.0));

try {
    $cli->enableSSL(function (){});
} catch (\Throwable $e) {
    Assert::contains($e->getMessage(), 'not support `onSslReady` callback');
}
?>
--EXPECT--
