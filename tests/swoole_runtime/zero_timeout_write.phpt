--TEST--
swoole_runtime: zero timeout stream write without waiting
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_php_version_lower_than('8.3');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Runtime;
use Swoole\Coroutine;

use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_ALL);

run(function () {
    $port = get_one_free_port();

    $server = null;
    $connection = null;

    // Server side: only accept, do not read data (so the client's send buffer gets filled up)
    go(function () use ($port, &$server, &$connection) {
        $server = stream_socket_server("tcp://127.0.0.1:{$port}", $errno, $errstr);
        Assert::true($server !== false, "server create failed: {$errstr}");

        $connection = stream_socket_accept($server, 5);
        Assert::true($connection !== false, "accept failed");

        // Suspend the coroutine and do not read the data sent by the client
        Coroutine::sleep(10);
    });

    $stream = stream_socket_client("tcp://127.0.0.1:{$port}", $errno, $errstr, 5);
    Assert::true($stream !== false, "connect failed: {$errstr}");

    // Set zero timeout
    stream_set_timeout($stream, 0, 0);

    // First fill up the send buffer (the swoole socket default sndbuf is about 128K, so write a bit more here)
    $payload = str_repeat('A', 1024 * 1024);

    $start = microtime(true);
    $written = @fwrite($stream, $payload);
    $elapsed = microtime(true) - $start;

    // With zero timeout, a write that cannot proceed should return immediately instead of blocking until the peer reads
    Assert::true($elapsed < 0.1, "zero-timeout write should return immediately, took {$elapsed}s");

    // It may have written part of the data (the part the buffer can hold), or it may return 0/false
    Assert::true($written === false || (is_int($written) && $written >= 0),
        "unexpected fwrite result: " . var_export($written, true));

    fclose($stream);
    if ($connection) {
        fclose($connection);
    }
    if ($server) {
        fclose($server);
    }
});

echo "OK\n";
?>
--EXPECT--
OK
