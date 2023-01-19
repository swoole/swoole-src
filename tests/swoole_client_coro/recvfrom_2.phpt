--TEST--
swoole_client_coro: recvfrom 2
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
const N = 10;
$free_port = get_one_free_port();

go(function () use ($free_port) {
    $cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_UDP);
    $cli->set([
        'bind_address' => '127.0.0.1',
        'bind_port' => $free_port,
    ]);
    $n = N;
    while ($n--) {
        $data = $cli->recvfrom(1024, $addr, $port);
        Assert::same($data, 'hello');
    }
    echo "DONE\n";
});

go(function () use ($free_port) {
    $socket = new Swoole\Coroutine\Socket(AF_INET, SOCK_DGRAM, 0);
    $n = N;
    while ($n--) {
        $socket->sendto('127.0.0.1', $free_port, "hello");
        Co::sleep(0.01);
    }
});
Swoole\Event::wait();
?>
--EXPECT--
DONE
