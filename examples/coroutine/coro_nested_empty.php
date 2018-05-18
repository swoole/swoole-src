<?php
require __DIR__ . "/coro_include.php";
function test()
{
    echo "before coro\n";
    go(function () {
        echo "co[1] start\n";
        go(function () {
            echo "co[2] start\n";
            echo "co[2] exit\n";
        });
        echo "co[1] exit\n";
    });
    echo "func end \n";
}
test();
