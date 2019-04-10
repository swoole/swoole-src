<?php
Swoole\Coroutine::set([
    'max_death_ms' => 2000,
]);
echo "start\n";
go(function () {
    echo "coro start\n";
    for ($i = 1; ; $i++) {
        echo $i."\n";
        sleep(1);
    }
});

go(function () {
    echo "222222\n";
});
echo "end\n";
