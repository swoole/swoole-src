--TEST--
swoole_client_coro: timeout of udp client[2]
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$port = get_one_free_port();

Co\Run(function () use ($port) {
    $cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_UDP);
    Assert::assert($cli->sendto('192.0.0.1', $port, 'hello'));
    $cli->set([
        'timeout' => 0.2,
    ]);
    // default timeout
    $s = microtime(true);
    $ret = @$cli->recvfrom(1024, $peer);
    $s = microtime(true) - $s;
    Assert::assert($s > 0.2 && $s < 0.5, $s);
    Assert::eq($ret, false);
    Assert::eq($cli->errCode, SOCKET_ETIMEDOUT);
    $cli->close();
});

?>
--EXPECT--
