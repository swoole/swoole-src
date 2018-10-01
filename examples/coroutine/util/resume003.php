<?php
go(function () {
    $count = 0;
    go(function () use (&$count) {
        echo "task 1 start\n";
        co::sleep(0.2);
        echo "task 1 resume count $count\n";
        if (++$count === 2) {
            co::resume(1);
        }
        echo "task 1 end\n";
    });
    go(function () use (&$count) {
        echo "task 2 start\n";
        co::sleep(0.1);
        echo "task 2 resume count $count\n";
        if (++$count === 2) {
            co::resume(1);
        }
        echo "task 2 end\n";
    });
    co::suspend();
});
echo "main \n";
