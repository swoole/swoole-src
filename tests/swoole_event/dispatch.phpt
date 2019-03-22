--TEST--
swoole_event: dispatch
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$id = swoole_timer_tick(100, function () {
    echo "Tick\n";
});

$n = 5;
while ($n--) {
    echo "loop\n";
    swoole_event_dispatch();
}

swoole_timer_clear($id);

?>
--EXPECT--
loop
loop
Tick
loop
Tick
loop
Tick
loop
Tick
