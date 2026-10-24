--TEST--
swoole_curl/multi: release a multi handle after an immediate timeout queues a resume
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--ENV--
USE_ZEND_ALLOC=0
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Swoole\Coroutine\Socket;
use Swoole\Runtime;

use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);

run(function (): void {
    $listener = new Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($listener->bind('127.0.0.1', 0));
    Assert::true($listener->listen());

    $ready = new Channel(1);
    $finish = new Channel(1);
    $port = $listener->getsockname()['port'];

    go(function () use ($listener, $ready, $finish): void {
        $peer = $listener->accept(1);
        Assert::true($peer instanceof Socket);
        Assert::true($peer->recv(4096, 1) !== false);
        Assert::true($ready->push(true, 1));
        Assert::true($finish->pop(1));
        $peer->close();
        $listener->close();
    });

    $multi = curl_multi_init();
    $http = curl_init("http://127.0.0.1:{$port}/");
    curl_setopt($http, CURLOPT_RETURNTRANSFER, true);
    curl_multi_add_handle($multi, $http);

    $cid = go(function () use (&$multi): void {
        $running = 1;
        while ($running) {
            curl_multi_exec($multi, $running);
            if ($running) {
                curl_multi_select($multi, 1);
            }
            if (Coroutine::isCanceled()) {
                return;
            }
        }
    });

    Assert::true($ready->pop(1));

    $file = curl_init('file://' . __FILE__);
    curl_setopt($file, CURLOPT_RETURNTRANSFER, true);
    curl_multi_add_handle($multi, $file);

    Assert::true(Coroutine::cancel($cid));
    curl_multi_remove_handle($multi, $file);
    curl_multi_remove_handle($multi, $http);
    unset($multi, $file, $http);

    $strings = [];
    for ($index = 0; $index < 64; ++$index) {
        $strings[] = str_repeat(chr(65 + $index % 26), 160 + $index);
    }

    Coroutine::sleep(0.001);
    Assert::true($finish->push(true, 1));
});

echo "DONE\n";
?>
--EXPECT--
DONE
