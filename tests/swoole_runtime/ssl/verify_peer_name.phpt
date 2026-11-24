--TEST--
swoole_runtime/ssl: hooked TLS client verifies the peer like ext/openssl
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_no_ssl();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

Swoole\Runtime::enableCoroutine();
swoole_async_set(['log_level' => SWOOLE_LOG_NONE]);

$ready = new Chan;

go(function () use ($ready) {
    $context = stream_context_create(['ssl' => [
        'local_cert' => SSL_FILE_DIR . '/server.crt',
        'local_pk' => SSL_FILE_DIR . '/server.key',
    ]]);
    $socket = stream_socket_server("ssl://127.0.0.1:0", $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $context);
    $ready->push((int) substr(strrchr(stream_socket_get_name($socket, false), ':'), 1));
    for ($i = 0; $i < 7; $i++) {
        $conn = @stream_socket_accept($socket, 2);
        if ($conn) {
            fclose($conn);
        }
    }
});

go(function () use ($ready) {
    $port = $ready->pop();
    $der = base64_decode(preg_replace('/-----[^-]+-----|\s/', '', file_get_contents(SSL_FILE_DIR . '/server.crt')));
    $cafile = SSL_FILE_DIR . '/ca.crt';
    $cases = [
        'defaults, untrusted CA' => [],
        'cafile' => ['cafile' => $cafile],
        'cafile, wrong peer_name' => ['cafile' => $cafile, 'peer_name' => 'other.example'],
        'cafile, verify_peer_name off' => ['cafile' => $cafile, 'verify_peer_name' => false],
        'verify_peer off' => ['verify_peer' => false, 'verify_peer_name' => false],
        'fingerprint match' => ['verify_peer' => false, 'verify_peer_name' => false, 'peer_fingerprint' => sha1($der)],
        'fingerprint mismatch' => ['verify_peer' => false, 'verify_peer_name' => false, 'peer_fingerprint' => str_repeat('0', 40)],
    ];
    foreach ($cases as $name => $options) {
        $fp = @stream_socket_client("ssl://127.0.0.1:{$port}", $errno, $errstr, 3, STREAM_CLIENT_CONNECT, stream_context_create(['ssl' => $options]));
        echo $name, ': ', $fp ? 'accepted' : 'refused', "\n";
        if ($fp) {
            fclose($fp);
        }
    }
});
?>
--EXPECT--
defaults, untrusted CA: refused
cafile: accepted
cafile, wrong peer_name: refused
cafile, verify_peer_name off: accepted
verify_peer off: accepted
fingerprint match: accepted
fingerprint mismatch: refused
