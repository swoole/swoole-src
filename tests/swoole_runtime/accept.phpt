--TEST--
swoole_runtime: accept
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_ssl();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

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
        $conn = stream_socket_accept($socket);
        fwrite($conn, 'The local time is ' . date('n/j/Y g:i a'));
        fclose($conn);
        fclose($socket);
    }
});

go(function () {
    $fp = stream_socket_client("tcp://127.0.0.1:8000", $errno, $errstr, 30);
    if (!$fp) {
        echo "$errstr ($errno)<br />\n";
    } else {
        $data = fread($fp, 8192);
        fclose($fp);
        Assert::assert(strpos($data,'local time') !== false);
    }
});

swoole_event_wait();
?>
--EXPECT--
