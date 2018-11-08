--TEST--
swoole_socket_coro: server and client concurrency
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
// it should be removed after php73 released
skip_php_version_between('7.3.0alpha1', '7.3.0RC4');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Swoole\Runtime::enableCoroutine();

$port = get_one_free_port();
$times = 128;
$greeter = 'Hello Swoole!';
$client_side_uid = go(function () use ($port, $times, $greeter) {
    co::yield();
    co::sleep(0.001);
    for ($c = $times; $c--;) {
        go(function () use ($port, $greeter) {
            $client = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, 0);
            assert($client->connect('127.0.0.1', $port));
            assert($client->recv() === $greeter);
            $client->close();
        });
    }
});
go(function () use ($port, $times, $greeter, $client_side_uid) {
    $socket = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    assert($socket->bind('127.0.0.1', $port));
    assert($socket->listen(2048));
    $i = 0;
    co::resume($client_side_uid); // able to accept connections
    while ($conn = $socket->accept()) {
        $conn->send($greeter);
        $conn->close();
        if (++$i === $times) {
            $socket->close();
            echo "DONE\n";
            break;
        }
    }
});

?>
--EXPECT--
DONE
