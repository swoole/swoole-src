<?php
echo "start\n";
go(function () {
    echo "coro start\n";
    loop:
    echo "111\n";
    sleep(1);
    goto loop;
});

go(function () {
    echo "222222\n";
});
echo "end\n";
