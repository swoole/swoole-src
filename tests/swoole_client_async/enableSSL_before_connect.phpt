--TEST--
swoole_client_async: enableSSL before connect
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$cli = new Swoole\Async\Client(SWOOLE_SOCK_TCP);
$res = $cli->enableSSL(function ($cli) {
    echo "SSL READY\n";
    $cli->send("GET / HTTP/1.1\r\nHost: www.baidu.com\r\nUser-Agent: curl/7.50.1-DEV\r\nAccept: */*\r\n\r\n");
});
Assert::false($res);

?>
--EXPECTF--
Warning: Swoole\Async\Client::enableSSL(): client is not connected to server in %s on line %d
