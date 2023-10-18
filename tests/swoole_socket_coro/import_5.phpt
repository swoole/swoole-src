--TEST--
swoole_socket_coro: import 5
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Co\run(function () {
    $sock = stream_socket_client(
        'tcp://www.baidu.com:80',
        $errno,
        $errstr,
        30
    );
    if (!$sock) {
        echo "$errstr ($errno)";
        return;
    }
    $socket = socket_import_stream($sock);
    if ($socket) {
        socket_write($socket, "GET / HTTP/1.0\r\nHost: www.baidu.com\r\nAccept: */*\r\n\r\n");
        $content = '';
        while (false !== ($tmp = socket_read($socket, 8192))) {
            if ('' === $tmp) {
                break;
            }
            $content .= $tmp;
        }
        socket_close($socket);
        Assert::assert(strpos($content, 'map.baidu.com') !== false);
    } else {
        echo 'import failed';
        return;
    }
});
?>
--EXPECT--
