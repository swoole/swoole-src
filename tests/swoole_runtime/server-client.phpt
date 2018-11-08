--TEST--
swoole_runtime: server and client concurrency
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Swoole\Runtime::enableCoroutine();

// tcp server & client
$port = get_one_free_port();
$times = 128; // system limit
$greeter = 'Hello Swoole!';
$client_side_uid = go(function () use ($port, $times, $greeter) {
    co::yield();
    co::sleep(0.001);
    for ($c = $times; $c--;) {
        go(function () use ($port, $greeter) {
            $fp = stream_socket_client("tcp://127.0.0.1:{$port}", $errno, $errstr, 1);
            if (!$fp) {
                echo "$errstr ($errno)\n";
            } else {
                $data = fread($fp, 8192);
                fclose($fp);
                assert($data === $greeter);
            }
        });
    }
});
go(function () use ($port, $times, $greeter, $client_side_uid) {
    $ctx = stream_context_create(['socket' => ['so_reuseaddr' => true, 'backlog' => 128]]);
    $socket = stream_socket_server(
        "tcp://127.0.0.1:{$port}",
        $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $ctx
    );
    if (!$socket) {
        echo "$errstr ($errno)\n";
    } else {
        co::resume($client_side_uid); // able to accept connections
        $i = 0;
        while ($conn = stream_socket_accept($socket, 10)) {
            fwrite($conn, $greeter);
            fclose($conn);
            if (++$i === $times) {
                fclose($socket);
                echo "DONE\n";
                break;
            }
        }
    }
});

?>
--EXPECT--
DONE
