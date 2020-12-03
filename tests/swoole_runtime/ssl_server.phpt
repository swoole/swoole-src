--TEST--
swoole_runtime: ssl server
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_ssl();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

swoole\runtime::enableCoroutine();

$ready = new Chan;

go(function () use ($ready) {
    $context = stream_context_create();
    stream_context_set_option($context, 'ssl', 'allow_self_signed', true);
    stream_context_set_option($context, 'ssl', 'verify_peer', false);
    stream_context_set_option($context, 'ssl', 'local_cert', SSL_FILE_DIR.'/server.crt');
    stream_context_set_option($context, 'ssl', 'local_pk', SSL_FILE_DIR.'/server.key');
    $socket = stream_socket_server("ssl://0.0.0.0:8000", $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $context);
    if (!$socket) {
        echo "$errstr ($errno)<br />\n";
    } else {
        $ready->push(true);
        $conn = stream_socket_accept($socket);
        fwrite($conn, 'The local time is ' . date('n/j/Y g:i a'));
        fclose($conn);
        fclose($socket);
        echo "OK\n";
    }
});

go(function () use ($ready) {
    $ready->pop();
    $fp = stream_socket_client("ssl://127.0.0.1:8000", $errno, $errstr, 30);
    if (!$fp) {
        echo "$errstr ($errno)<br />\n";
    } else {
        $data = fread($fp, 8192);
        fclose($fp);
        Assert::assert(strpos($data,'local time') !== false);
        echo "OK\n";
    }
});

swoole_event_wait();
?>
--EXPECT--
OK
OK
