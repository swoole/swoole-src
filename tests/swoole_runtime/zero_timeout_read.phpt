--TEST--
swoole_runtime: zero timeout stream read without waiting
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Runtime;
use Swoole\Coroutine;
use Swoole\Coroutine\Channel;

use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_ALL);

run(function () {
    $port = get_one_free_port();

    $chan = new Channel(1);

    $server = null;
    $connection = null;

    go(function () use ($port, &$server, &$connection, $chan) {
        $server = stream_socket_server("tcp://127.0.0.1:{$port}", $errno, $errstr);
        Assert::true($server !== false, "server create failed: {$errstr}");

        $connection = stream_socket_accept($server, 5);
        Assert::true($connection !== false, "accept failed");

        // Send data only after the client has done its zero-timeout read.
        Assert::true($chan->pop(30) !== false, "server was not released");
        fwrite($connection, "line\nrecord1\n");
    });

    $stream = stream_socket_client("tcp://127.0.0.1:{$port}", $errno, $errstr, 5);
    Assert::true($stream !== false, "connect failed: {$errstr}");

    stream_set_timeout($stream, 0, 0);

    $start = microtime(true);
    Assert::same(fread($stream, 8192), "");
    $elapsed = microtime(true) - $start;
    Assert::true($elapsed < 0.1, "zero-timeout read should return immediately, took {$elapsed}s");

    $meta = stream_get_meta_data($stream);
    Assert::false($meta['timed_out']);
    Assert::false($meta['eof']);

    // Release the server and poll with a bounded deadline so a regression cannot hang the test.
    $chan->push(true);

    $data = "";
    $deadline = microtime(true) + 5;
    while ($data === "" && microtime(true) < $deadline) {
        $data = fread($stream, 8192);
        if ($data === "") {
            Coroutine::sleep(0.05);
        }
    }
    Assert::same($data, "line\nrecord1\n");

    fclose($stream);
    fclose($connection);
    fclose($server);
});

echo "OK\n";
?>
--EXPECT--
OK
