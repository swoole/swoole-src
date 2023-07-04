--TEST--
swoole_coroutine_wait_group: run in defer
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Co\run(function () {
    $wg = new Swoole\Coroutine\WaitGroup();
    foreach (range(1, 2) as $i) {
        var_dump("add $i");
        $wg->add();
        Co\go(function () use ($wg, $i) {
            var_dump("start $i");
            defer(function () use ($wg, $i) {
                var_dump("defer $i");
                $wg->done();
                var_dump("done $i");
            });
            var_dump("end $i");
        });
    }

    var_dump("wait");
    $wg->wait();
    var_dump("finish");
});

?>
--EXPECT--
string(5) "add 1"
string(7) "start 1"
string(5) "end 1"
string(7) "defer 1"
string(6) "done 1"
string(5) "add 2"
string(7) "start 2"
string(5) "end 2"
string(7) "defer 2"
string(6) "done 2"
string(4) "wait"
string(6) "finish"
