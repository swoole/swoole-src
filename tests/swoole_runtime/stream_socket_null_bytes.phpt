--TEST--
swoole_runtime: TCP and UDP streams reject embedded null bytes like native PHP
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

function check_stream_addresses(bool $checkBindto): array
{
    $errors = [];
    foreach (['tcp', 'udp'] as $protocol) {
        $flags = STREAM_SERVER_BIND | ($protocol === 'tcp' ? STREAM_SERVER_LISTEN : 0);
        foreach ([
            '127.0.0.1' . "\0" . 'ignored:0',
            '127.0.0.1:0' . "\0" . 'ignored',
            '[::1' . "\0" . 'ignored]:0',
            '[::1]:0' . "\0" . 'ignored',
        ] as $address) {
            $server = @stream_socket_server($protocol . '://' . $address, $errno, $error, $flags);
            if (is_resource($server)) {
                fclose($server);
            }
            Assert::false($server);
            Assert::same($error, 'The hostname must not contain null bytes');
            $errors[] = $error;
        }
        $server = stream_socket_server($protocol . '://127.0.0.1:0', $errno, $error, $flags);
        Assert::true(is_resource($server));
        fclose($server);
    }

    $listener = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
    Assert::true(is_resource($listener));
    try {
        $endpoint = stream_socket_get_name($listener, false);
        $port = substr(strrchr($endpoint, ':'), 1);
        foreach ([
            '127.0.0.1' . "\0" . 'ignored:' . $port,
            '127.0.0.1:' . $port . "\0ignored",
            '[::1' . "\0" . 'ignored]:' . $port,
            '[::1]:' . $port . "\0ignored",
        ] as $address) {
            $client = @stream_socket_client('tcp://' . $address, $errno, $error, 0.5);
            if (is_resource($client)) {
                fclose($client);
            }
            Assert::false($client);
            Assert::same($error, 'The hostname must not contain null bytes');
            $errors[] = $error;
        }
        if ($checkBindto) {
            // Native PHP ignores failed bindto parsing; Swoole already rejects invalid context addresses.
            foreach (["127.0.0.1\0ignored:0", "127.0.0.1:0\0ignored"] as $bindto) {
                $context = stream_context_create(['socket' => ['bindto' => $bindto]]);
                $client = @stream_socket_client('tcp://' . $endpoint, $errno, $error, 0.5, STREAM_CLIENT_CONNECT, $context);
                if (is_resource($client)) {
                    fclose($client);
                }
                Assert::false($client);
                Assert::same($error, 'The hostname must not contain null bytes');
            }
        }
        $client = stream_socket_client('tcp://' . $endpoint, $errno, $error, 0.5);
        Assert::true(is_resource($client));
        $peer = stream_socket_accept($listener, 0.5);
        Assert::true(is_resource($peer));
        fclose($peer);
        fclose($client);
    } finally {
        fclose($listener);
    }
    return $errors;
}

$native = check_stream_addresses(false);
Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_TCP | SWOOLE_HOOK_UDP);
Swoole\Coroutine\run(static function () use ($native) {
    Assert::same(check_stream_addresses(true), $native);
});
echo "DONE\n";
?>
--EXPECT--
DONE
