--TEST--
swoole_runtime: zero timeout stream write without waiting
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Runtime;
use Swoole\Coroutine\Channel;

use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_ALL);

run(function () {
    $port = get_one_free_port();

    $chan = new Channel(1);

    $server = null;
    $connection = null;

    // Server side: only accept, never read, so the client send buffer fills up.
    go(function () use ($port, &$server, &$connection, $chan) {
        $server = stream_socket_server("tcp://127.0.0.1:{$port}", $errno, $errstr);
        Assert::true($server !== false, "server create failed: {$errstr}");

        $connection = stream_socket_accept($server, 5);
        Assert::true($connection !== false, "accept failed");

        // Wait for the test body to finish instead of sleeping for a fixed duration.
        $chan->pop(30);
    });

    $stream = stream_socket_client("tcp://127.0.0.1:{$port}", $errno, $errstr, 5);
    Assert::true($stream !== false, "connect failed: {$errstr}");

    // Fill the send buffer in non-blocking mode until no further bytes are accepted.
    stream_set_blocking($stream, false);
    $payload = str_repeat('A', 8192);
    $deadline = microtime(true) + 10;
    do {
        $written = @fwrite($stream, $payload);
    } while ($written > 0 && microtime(true) < $deadline);
    Assert::true(microtime(true) < $deadline, "failed to fill the send buffer");

    // Explicitly non-blocking stream: a full send buffer is reported as a zero-byte write,
    // without setting timed_out or eof (same as native PHP).
    $start = microtime(true);
    $written = @fwrite($stream, 'x');
    Assert::same($written, 0);
    Assert::true(microtime(true) - $start < 0.1, "non-blocking write should return immediately");

    $meta = stream_get_meta_data($stream);
    Assert::false($meta['timed_out']);
    Assert::false($meta['eof']);

    // Blocking stream with zero timeout: native PHP fails the write and sets timed_out
    // when the send buffer is full, instead of reporting a zero-byte write.
    stream_set_blocking($stream, true);
    stream_set_timeout($stream, 0, 0);

    $start = microtime(true);
    $written = @fwrite($stream, 'x');
    $elapsed = microtime(true) - $start;
    Assert::same($written, false);
    Assert::true($elapsed < 0.1, "zero-timeout write should return immediately, took {$elapsed}s");

    $meta = stream_get_meta_data($stream);
    Assert::true($meta['timed_out']);
    Assert::false($meta['eof']);

    fclose($stream);
    $chan->push(true);
});

echo "OK\n";
?>
--EXPECT--
OK
