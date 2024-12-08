--TEST--
swoole_client_async: enableSSL with bad callback
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$cli = new Swoole\Async\Client(SWOOLE_SOCK_TCP);
try {
    $res = $cli->enableSSL();
} catch (Exception $e) {
    Assert::contains($e->getMessage(), 'require `onSslReady` callback');
}
?>
--EXPECTF--
