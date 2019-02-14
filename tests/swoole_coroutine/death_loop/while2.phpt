--TEST--
swoole_coroutine: while without opcache enable
--SKIPIF--
<?php  
require __DIR__ . '/../../include/skipif.inc';
 if (ini_get("opcache.enable_cli") == 1) 
 {
    skip("has loaded opcache");
 }
?>
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
    while(!$exit) {
        $i ++;
        echo "coro 1 $i\n";
        //0.1 s
        usleep(100000);
    }
    echo "coro 1 exit\n";
});

go(function () use (&$exit) {
    echo "coro 2 start\n";
    $i = 0;
    while(!$exit) {
        $i ++;
        echo "coro 2 $i\n";
        //0.1 s
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
coro 1 1
coro 1 2
coro 1 3
coro 1 4
coro 1 5
coro 1 6
coro 1 7
coro 1 8
coro 1 9
coro 1 10
coro 1 11
coro 1 12
coro 1 13
coro 1 14
coro 1 15
coro 1 16
coro 1 17
coro 1 18
coro 1 19
coro 1 20
coro 2 start
coro 2 1
coro 2 2
coro 2 3
coro 2 4
coro 2 5
coro 2 6
coro 2 7
coro 2 8
coro 2 9
coro 2 10
coro 2 11
coro 2 12
coro 2 13
coro 2 14
coro 2 15
coro 2 16
coro 2 17
coro 2 18
coro 2 19
coro 2 20
coro 3 start
end
coro 1 21
coro 1 exit
coro 2 21
coro 2 exit
