--TEST--
swoole_runtime: stream_get_meta_data timed_out is reset by a later successful operation
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

    $ready = new Channel(1);
    $ask = new Channel(1);
    $sent = new Channel(1);
    $release = new Channel(1);

    // Server side: never reads, so the client send buffer fills up. It sends one byte only when the
    // test body asks for it and acknowledges the queued byte, so the recovery read finds data ready.
    go(function () use ($port, &$server, &$connection, $ready, $ask, $sent, $release) {
        $server = stream_socket_server("tcp://127.0.0.1:{$port}", $errno, $errstr);
        Assert::true($server !== false, "server create failed: {$errstr}");

        $connection = stream_socket_accept($server, 5);
        Assert::true($connection !== false, "accept failed");
        $ready->push(true);

        foreach (['r', 's'] as $byte) {
            $ask->pop(30);
            Assert::same(fwrite($connection, $byte), 1);
            $sent->push(true);
        }

        // Wait for the test body to finish instead of sleeping for a fixed duration.
        $release->pop(30);
    });

    $stream = stream_socket_client("tcp://127.0.0.1:{$port}", $errno, $errstr, 5);
    Assert::true($stream !== false, "connect failed: {$errstr}");
    Assert::true($ready->pop(30) !== false, "the server did not accept the connection");

    // Fill the send buffer, then let a blocking zero-timeout write fail: this is the timeout to recover from.
    stream_set_blocking($stream, false);
    $payload = str_repeat('A', 8192);
    $deadline = microtime(true) + 10;
    do {
        $written = @fwrite($stream, $payload);
    } while ($written > 0 && microtime(true) < $deadline);
    Assert::true(microtime(true) < $deadline, "failed to fill the send buffer");

    stream_set_blocking($stream, true);
    stream_set_timeout($stream, 0, 0);
    Assert::same(@fwrite($stream, 'x'), false);

    $meta = stream_get_meta_data($stream);
    Assert::true($meta['timed_out']);
    Assert::false($meta['eof']);

    // A successful blocking read must clear the timeout state left by the failed write.
    stream_set_timeout($stream, 0, 200000);
    $ask->push(true);
    Assert::true($sent->pop(30) !== false, "the server did not send 'r'");
    Assert::same(fread($stream, 1), 'r');

    $meta = stream_get_meta_data($stream);
    Assert::false($meta['timed_out']);
    Assert::false($meta['eof']);

    // A read that does time out reports it again, still without setting eof.
    $start = microtime(true);
    Assert::false(fread($stream, 1));
    $elapsed = microtime(true) - $start;
    Assert::greaterThanEq($elapsed, 0.1, "read should wait for the timeout, took {$elapsed}s");
    Assert::lessThan($elapsed, 0.5, "read timeout should be 200ms, took {$elapsed}s");

    $meta = stream_get_meta_data($stream);
    Assert::true($meta['timed_out']);
    Assert::false($meta['eof']);

    // and the next successful read clears it once more.
    $ask->push(true);
    Assert::true($sent->pop(30) !== false, "the server did not send 's'");
    Assert::same(fread($stream, 1), 's');

    $meta = stream_get_meta_data($stream);
    Assert::false($meta['timed_out']);
    Assert::false($meta['eof']);

    fclose($stream);
    $release->push(true);
});

echo "OK\n";
?>
--EXPECT--
OK
