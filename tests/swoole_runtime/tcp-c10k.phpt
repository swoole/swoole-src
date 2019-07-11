--TEST--
swoole_runtime: server and client concurrency
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Swoole\Runtime::enableCoroutine();

// php_stream tcp server & client with 12.8k requests in single process
$port = get_one_free_port();

go(function () use ($port) {
    $ctx = stream_context_create(['socket' => ['so_reuseaddr' => true, 'backlog' => MAX_CONCURRENCY_MID]]);
    $socket = stream_socket_server(
        "tcp://0.0.0.0:{$port}",
        $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $ctx
    );
    if (!$socket) {
        echo "$errstr ($errno)\n";
    } else {
        $i = 0;
        while ($conn = stream_socket_accept($socket, 1)) {
            for ($n = MAX_REQUESTS; $n--;) {
                $data = fread($conn, tcp_length(fread($conn, tcp_type_length())));
                Assert::same($data, "Hello Swoole Server #{$n}!");
                fwrite($conn, tcp_pack("Hello Swoole Client #{$n}!"));
            }
            if (++$i === MAX_CONCURRENCY_MID) {
                fclose($socket);
                echo "DONE\n";
                break;
            }
        }
    }
});
for ($c = MAX_CONCURRENCY_MID; $c--;) {
    go(function () use ($port) {
        $fp = stream_socket_client("tcp://127.0.0.1:{$port}", $errno, $errstr, 1);
        if (!$fp) {
            echo "$errstr ($errno)\n";
        } else {
            for ($n = MAX_REQUESTS; $n--;) {
                fwrite($fp, tcp_pack("Hello Swoole Server #{$n}!"));
                $data = fread($fp, tcp_length(fread($fp, tcp_type_length())));
                Assert::same($data, "Hello Swoole Client #{$n}!");
            }
            fclose($fp);
        }
    });
}

?>
--EXPECT--
DONE
