--TEST--
swoole_feature/cross_close: stream closed by server
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
Swoole\Runtime::enableCoroutine();
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        $fp = stream_socket_client("tcp://127.0.0.1:{$pm->getFreePort()}", $errno, $errstr, 1);
        if (!$fp) {
            exit("$errstr ($errno)\n");
        } else {
            echo "WRITE\n";
            Assert::same(fwrite($fp, ($data = tcp_pack("Hello Swoole Server!"))), strlen($data));
            echo "READ\n";
            Assert::same(fread($fp, 1024), '');
            echo "CLOSED\n";
            fclose($fp);
            echo "DONE\n";
        }
    });
};
$pm->childFunc = function () use ($pm) {
    go(function () use ($pm) {
        $ctx = stream_context_create(['socket' => ['so_reuseaddr' => true, 'backlog' => MAX_CONCURRENCY_MID]]);
        $server = stream_socket_server(
            "tcp://127.0.0.1:{$pm->getFreePort()}",
            $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $ctx
        );
        if (!$server) {
            exit("$errstr ($errno)\n");
        } else {
            go(function () use ($server) {
                if ($conn = stream_socket_accept($server, 1)) {
                    switch_process();
                    Assert::same(fread($conn, tcp_length(fread($conn, tcp_type_length()))), "Hello Swoole Server!");
                    echo "CLOSE\n";
                    fclose($conn);
                    switch_process();
                }
                fclose($server);
            });
        }
        $pm->wakeup();
    });
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--

WRITE
READ
CLOSE
CLOSED
DONE
