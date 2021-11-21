--TEST--
swoole_runtime: accept timeout
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Swoole\Runtime::enableCoroutine();

go(function () {
    $opts = array(
        'socket' => array(
            'so_reuseaddr' => true,
        ),
    );
    $ctx = stream_context_create($opts);
    $socket = stream_socket_server("tcp://0.0.0.0:8000", $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $ctx);
    if (!$socket) {
        echo "$errstr ($errno)<br />\n";
    } else {
        $conn = @stream_socket_accept($socket, 1);
        Assert::false($conn);
    }
});

Swoole\Event::wait();
?>
--EXPECT--
