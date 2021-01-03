--TEST--
swoole_runtime: nonblock
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Co\run(function () {
    $socket = stream_socket_client(
        'tcp://www.baidu.com:80',
        $errorCode,
        $errorMessage,
        1,
        STREAM_CLIENT_CONNECT
    );
    stream_set_timeout($socket, 5);
    stream_set_blocking($socket, false);
    $receivedData = fread($socket, 1);
    Assert::assert($receivedData === '');
});
?>
--EXPECT--
