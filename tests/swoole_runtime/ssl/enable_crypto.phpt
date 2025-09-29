--TEST--
swoole_runtime/ssl: stream_socket_enable_crypto
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_no_ssl();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

Swoole\Runtime::enableCoroutine();

$ready = new Chan;

go(function () use ($ready) {
    $context = stream_context_create();
    stream_context_set_option($context, 'ssl', 'allow_self_signed', true);
    stream_context_set_option($context, 'ssl', 'verify_peer', true);
    stream_context_set_option($context, 'ssl', 'local_cert', SSL_FILE_DIR.'/server.crt');
    stream_context_set_option($context, 'ssl', 'local_pk', SSL_FILE_DIR.'/server.key');
    stream_context_set_option($context, 'ssl', 'cafile', SSL_FILE_DIR.'/ca.crt');

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

    $fp = stream_socket_client("tcp://127.0.0.1:8000", $errno, $errstr, 30);
    if (!$fp) {
        echo "$errstr ($errno)<br />\n";
    } else {
        stream_context_set_option($fp, ["ssl" => [
            "local_cert" => SSL_FILE_DIR . '/client.crt',
            "local_pk" => SSL_FILE_DIR . '/client.key',
        ]]);
        // Enable SSL encryption after the connection is established
        Assert::assert(stream_socket_enable_crypto($fp, true, STREAM_CRYPTO_METHOD_TLS_CLIENT));
        $data = fread($fp, 8192);
        fclose($fp);
        Assert::assert(strpos($data, 'local time') !== false);
        echo "OK\n";
    }
});

Swoole\Event::wait();
?>
--EXPECT--
OK
OK
