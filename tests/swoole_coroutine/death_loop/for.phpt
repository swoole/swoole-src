--TEST--
swoole_coroutine: for
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
Swoole\Coroutine::set([
    'max_death_ms' => 2000,
    'death_loop_threshold' => 20,
]);
$exit = false;
echo "start\n";
go(function () use (&$exit) {
    echo "coro 1 start\n";
    $i = 0;
    for (;;) {
        $i++;
        echo "coro1 $i \n";
        if ($exit) {
            break;
        }
        usleep(100000);
    }
    echo "coro 1 exit\n";
});

go(function () use (&$exit) {
    echo "coro 2 start\n";
    $i = 0;
    for (;;) {
        $i++;
        echo "coro2 $i \n";
        if ($exit) {
            break;
        }
        usleep(100000);
    }
    echo "coro 2 exit\n";
});

go(function () use (&$exit) {
    echo "coro 3 start\n";
    $exit = 1;
});
echo "end\n";
?>
--EXPECTF--
start
coro 1 start
coro1 1 
coro1 2 
coro1 3 
coro1 4 
coro1 5 
coro1 6 
coro1 7 
coro1 8 
coro1 9 
coro1 10 
coro1 11 
coro1 12 
coro1 13 
coro1 14 
coro1 15 
coro1 16 
coro1 17 
coro1 18 
coro1 19 
coro1 20 
coro 2 start
coro2 1 
coro2 2 
coro2 3 
coro2 4 
coro2 5 
coro2 6 
coro2 7 
coro2 8 
coro2 9 
coro2 10 
coro2 11 
coro2 12 
coro2 13 
coro2 14 
coro2 15 
coro2 16 
coro2 17 
coro2 18 
coro2 19 
coro2 20 
coro 3 start
end
coro1 21 
coro 1 exit
coro2 21 
coro 2 exit
