--TEST--
swoole_runtime: stream_socket_accept peer name
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Swoole\Runtime::enableCoroutine();

$chan = new Swoole\Coroutine\Channel(1);

go(function () use ($chan) {
    $server = stream_socket_server("tcp://127.0.0.1:0", $errno, $errstr);
    Assert::true(is_resource($server));
    $addr = stream_socket_get_name($server, false);
    $port = (int) substr(strrchr($addr, ':'), 1);
    $chan->push($port);

    $peername = null;
    $conn = stream_socket_accept($server, 5, $peername);
    Assert::true(is_resource($conn));
    Assert::true(strpos($peername, '127.0.0.1:') === 0);

    fwrite($conn, "OK\n");
    fclose($conn);
    fclose($server);
});

go(function () use ($chan) {
    $port = $chan->pop();
    $client = stream_socket_client("tcp://127.0.0.1:{$port}");
    Assert::true(is_resource($client));
    echo fread($client, 3);
    fclose($client);
});

Swoole\Event::wait();
?>
--EXPECT--
OK
