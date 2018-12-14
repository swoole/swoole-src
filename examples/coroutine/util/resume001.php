<?php
go(function () {
    $main = co::getuid();
    echo "start to create coro\n";
    go(function () use ($main) {
        echo "coro 2\n";
        co::sleep(0.1);
        echo "resume\n";
        co::resume($main);
    });
    echo "before suspend \n";
    co::suspend();
    echo "after suspend \n";
});
echo "main \n";
