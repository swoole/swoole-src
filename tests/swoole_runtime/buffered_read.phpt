--TEST--
swoole_runtime: return buffered stream data without waiting
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_php_version_lower_than('8.3');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Channel;
use Swoole\Runtime;

use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_TCP);

run(function () {
    $port = get_one_free_port();
    $release = new Channel(1);

    go(function () use ($port, $release) {
        $server = stream_socket_server("tcp://127.0.0.1:{$port}", $errno, $errstr);
        $connection = stream_socket_accept($server);
        fwrite($connection, "line\nrecord1\n");
        $release->pop();
        fwrite($connection, "record2\n");
        fclose($connection);
        fclose($server);
    });

    $stream = stream_socket_client("tcp://127.0.0.1:{$port}", $errno, $errstr);
    Assert::same(fgets($stream), "line\n");

    go(function () use ($release) {
        Co::sleep(0.01);
        $release->push(true);
    });

    Assert::same(fread($stream, 8192), "record1\n");
    Assert::same(fread($stream, 8192), "record2\n");
    fclose($stream);
});
?>
--EXPECT--
