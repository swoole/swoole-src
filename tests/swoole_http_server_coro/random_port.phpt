--TEST--
swoole_http_server_coro: bind random port
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function() {
    $server = new Co\Http\Server("127.0.0.1", 0);
    Assert::assert($server->port > 0 and $server->port < 65535);
});

?>
--EXPECT--
