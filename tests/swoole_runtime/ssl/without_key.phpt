--TEST--
swoole_runtime/ssl: reject unpaired client certificate and key settings
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_no_ssl();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

Swoole\Runtime::enableCoroutine();
Swoole\Coroutine\run(function () {
    foreach ([
        ['local_cert', 'client.crt', 'ssl require key file'],
        ['local_pk', 'client.key', 'ssl require cert file'],
    ] as [$option, $file, $message]) {
        $context = stream_context_create(['ssl' => [$option => SSL_FILE_DIR . '/' . $file]]);
        try {
            @stream_socket_client('ssl://127.0.0.1:1', $errno, $errstr, 1, STREAM_CLIENT_CONNECT, $context);
            Assert::true(false, 'unpaired certificate and key must throw before connecting');
        } catch (Swoole\Exception $exception) {
            Assert::same($exception->getCode(), SWOOLE_ERROR_INVALID_PARAMS);
            Assert::same($exception->getMessage(), $message);
        }
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
