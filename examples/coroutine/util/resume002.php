<?php
go(function () {
    echo "coro 1 start\n";
    co::suspend();
    echo "coro 1 end\n";
});
echo "main 1\n";
go(function () {
    echo "coro 2 start\n";
    co::resume(1);
    echo "coro 2 end\n";
});
echo "main 2\n";
