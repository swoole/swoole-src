--TEST--
swoole_client_coro: timeout of udp client
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$port = get_one_free_port();

$cid = go(function () use ($port) {
    $socket = new Swoole\Coroutine\Socket(AF_INET, SOCK_DGRAM, 0);
    $socket->bind('127.0.0.1', $port);
    $peer = null;
    $socket->recvfrom($peer);
    echo "recvfrom client\n";
});

go(function () use ($port) {
    co::set([
        'socket_connect_timeout' => 0.5,
        'socket_timeout' => 0.1
    ]);

    $cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_UDP);
    if (!Assert::assert($cli->connect('127.0.0.1', $port))) {
        return;
    }

    Assert::assert($cli->send("hello"));

    // default timeout
    $s = microtime(true);
    $ret = @$cli->recv();
    $s = microtime(true) - $s;
    Assert::assert($s > 0.08 && $s < 0.12, $s);
    Assert::assert(!$ret, var_dump_return($ret));

    // custom timeout
    $s = microtime(true);
    $ret = @$cli->recv(0.5);
    $s = microtime(true) - $s;
    Assert::assert($s > 0.45 && $s < 0.55, $s);
    Assert::assert(!$ret, var_dump_return($ret));

    // default timeout
    $s = microtime(true);
    $ret = @$cli->recv();
    $s = microtime(true) - $s;
    Assert::assert($s > 0.08 && $s < 0.12, $s);
    Assert::assert(!$ret, var_dump_return($ret));

    $cli->close();
    echo "TIMEOUT\n";
});

swoole_event::wait();
?>
--EXPECT--
recvfrom client
TIMEOUT
