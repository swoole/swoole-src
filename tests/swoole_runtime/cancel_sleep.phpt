--TEST--
swoole_runtime: cancel sleep
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Swoole\Runtime::enableCoroutine();

use Swoole\Coroutine;
use Swoole\Coroutine\System;
use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;

run(function() {
    $cid = Coroutine::getCid();
    go(function() use ($cid) {
        System::sleep(2);
        Coroutine::cancel($cid);
    });

    Assert::false(System::sleep(2000));
    echo "success1" . PHP_EOL;

    $cids = [];
    for($i = 0; $i < 100; $i++) {
        $cids[] = go(function() use ($cid) {
            Assert::false(System::sleep(100));
        });
    }

    go(function() use ($cid) {
        Assert::true(System::sleep(2));
        echo "success3" . PHP_EOL;
    });

    foreach($cids as $cid) {
        Coroutine::cancel($cid);
    }

    echo "success2" . PHP_EOL;
});
?>
--EXPECT--
success1
success2
success3
