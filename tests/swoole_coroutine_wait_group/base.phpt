--TEST--
swoole_coroutine_wait_group: base
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\System;
use Swoole\Coroutine\WaitGroup;

$wg = new WaitGroup;
Co\run(function () use ($wg) {
    go(function () use ($wg) {
        $wg->add();
        Assert::same(
            file_get_contents(__FILE__),
            System::readFile(__FILE__)
        );
        echo "TASK[1] DONE\n";
        $wg->done();
    });
    $cid = go(function () use ($wg) {
        $wg->add();
        Assert::true(Co::yield());
        echo "TASK[2] DONE\n";
        $wg->done();
    });
    go(function () use ($wg, $cid) {
        $wg->add();
        Assert::notSame(Co::sleep(0.001), false);
        Co::resume($cid);
        echo "TASK[3] DONE\n";
        $wg->done();
    });
    $wg->wait();
});
?>
--EXPECTF--
TASK[%d] DONE
TASK[%d] DONE
TASK[%d] DONE
