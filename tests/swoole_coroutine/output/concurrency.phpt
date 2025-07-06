--TEST--
swoole_coroutine/output: concurrency
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
ob_start();
echo "cid 0\n";

Co\run(function () {
    ob_start();
    echo "cid 1\n";

    $list = [];
    $n = MAX_REQUESTS;
    while ($n--) {
        $list[] = Co\go(function () {
            ob_start();
            $cid = co::getCid();
            echo "cid {$cid} [1]\n";
            usleep(random_int(1000, 5000));
            echo "cid {$cid} [2]\n";
            usleep(random_int(1000, 5000));
            echo "cid {$cid} [3]\n";
            usleep(random_int(1000, 5000));
            Assert::eq(
                ob_get_clean(),
                implode('', [
                    "cid {$cid} [1]\n",
                    "cid {$cid} [2]\n",
                    "cid {$cid} [3]\n",
                ])
            );
        });
    }
    co::join($list);

    Assert::eq(ob_get_clean(), "cid 1\n");
});

Assert::eq(ob_get_clean(), "cid 0\n");
?>
--EXPECT--
