--TEST--
swoole_runtime: zero timeout stream data without waiting
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
use Swoole\Coroutine\Channel;

use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_ALL);

run(function () {
    $port = get_one_free_port();
    $ready = new Channel(1);

    go(function () use ($port, $ready) {
        $server = stream_socket_server("tcp://127.0.0.1:{$port}", $errno, $errstr);
        Assert::true($server !== false, "server create failed: {$errstr}");

        $ready->push(true);

        $connection = stream_socket_accept($server, 5);
        Assert::true($connection !== false, "accept failed");

        Coroutine::sleep(0.5);
        fwrite($connection, "line\nrecord1\n");

        fclose($connection);
        fclose($server);
    });

    $ready->pop();

    $stream = stream_socket_client("tcp://127.0.0.1:{$port}", $errno, $errstr, 5);
    Assert::true($stream !== false, "connect failed: {$errstr}");

    stream_set_timeout($stream, 0, 0);

    $start = microtime(true);
    Assert::same(fread($stream, 8192), "");
    $elapsed = microtime(true) - $start;
    Assert::true($elapsed < 0.1, "zero-timeout read should return immediately, took {$elapsed}s");

    Assert::false(feof($stream));

    $data = fread($stream, 8192);
    Assert::same($data, "line\nrecord1\n");

    fclose($stream);
});

echo "OK\n";
?>
--EXPECT--
OK