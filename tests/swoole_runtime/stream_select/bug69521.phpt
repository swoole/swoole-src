--TEST--
swoole_runtime/stream_select: Bug #69521 Segfault in gc_collect_cycles()
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
Swoole\Runtime::enableCoroutine();
go(function () {
    $serverUri = "tcp://127.0.0.1:64321";
    $sock = stream_socket_server($serverUri, $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN);

    $fp = stream_socket_client($serverUri, $errNumber, $errString, 5, STREAM_CLIENT_CONNECT);

    $written = 0;

    $data = "test";
    $written += fwrite($fp, substr($data, $written, 100));

    $link = stream_socket_accept($sock);
    fread($link, 1000);
    fwrite($link, "Sending bug 69521\n");
    fclose($link);

    while (!feof($fp)) {
        $read = $write = [$fp];

        if ($written === strlen($data)) {
            $write = [];
        }

        stream_select($read, $write, $except, 0, 500000);

        if (!empty($read)) {
            echo fread($fp, 4);
        }
    }
});
Swoole\Event::wait();
?>
--EXPECT--
Sending bug 69521
