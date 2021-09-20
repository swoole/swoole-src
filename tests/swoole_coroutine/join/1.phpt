--TEST--
swoole_coroutine/join: 1
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;
use Swoole\Coroutine;

run(function () {
    $result = [];
    Assert::true(Coroutine::join([
        go(function () use (&$result) {
            $result['baidu'] = file_get_contents("https://www.baidu.com/");
        }),
        go(function () use (&$result) {
            $result['taobao'] = file_get_contents("https://www.taobao.com/");
        })
    ]));

    echo "ALL DONE\n";
    Assert::contains($result['baidu'], 'baidu.com');
    Assert::contains($result['taobao'], 'taobao.com');
});
?>
--EXPECT--
ALL DONE
