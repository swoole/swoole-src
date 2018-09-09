--TEST--
swoole_runtime: accept timeout
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
if (!defined("SWOOLE_SSL")) {
    echo "skip";
}
?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';

swoole\runtime::enableCoroutine();

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
        assert($conn == false);
    }
});

swoole_event_wait();
?>
--EXPECT--

