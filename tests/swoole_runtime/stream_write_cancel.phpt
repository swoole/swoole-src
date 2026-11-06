--TEST--
swoole_runtime: cancel a partially sent stream write
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--INI--
default_socket_timeout=5
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Runtime;

use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_ALL);

run(function () {
    [$reader, $writer] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
    $cid = Coroutine::getCid();
    go(function () use ($cid) {
        Coroutine::sleep(0.2);
        Assert::true(Coroutine::cancel($cid));
    });

    $start = microtime(true);
    Assert::false(@fwrite($writer, str_repeat('x', 8 * 1024 * 1024)));
    Assert::lessThan(microtime(true) - $start, 1);

    fclose($writer);
    Assert::greaterThan(strlen(stream_get_contents($reader)), 0);
    fclose($reader);
});
?>
--EXPECT--
