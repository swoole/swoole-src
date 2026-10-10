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

use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_ALL);

run(function () {
    $port = get_one_free_port();

    $server = null;
    $connection = null;

    go(function () use ($port, &$server, &$connection) {
        $server = stream_socket_server("tcp://127.0.0.1:{$port}", $errno, $errstr);
        Assert::true($server !== false, "server create failed: {$errstr}");

        $connection = stream_socket_accept($server, 5);
        Assert::true($connection !== false, "accept failed");

        Coroutine::sleep(1.5);
        fwrite($connection, "line\nrecord1\n");
    });


    $stream = stream_socket_client("tcp://127.0.0.1:{$port}", $errno, $errstr, 5);
    Assert::true($stream !== false, "connect failed: {$errstr}");

    stream_set_timeout($stream, 0, 0);

    $start = microtime(true);
    Assert::same(fread($stream, 8192), "");
    $elapsed = microtime(true) - $start;
    Assert::true($elapsed < 0.1, "zero-timeout read should return immediately, took {$elapsed}s");

    Assert::false(feof($stream));

    $data = '';
    while(!$data) {
        $data = fread($stream, 8192);
        Coroutine::sleep(0.2);
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