--TEST--
swoole_event: swoole_event_exit
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--

<?php
require __DIR__ . '/../include/bootstrap.php';

swoole_timer_tick(1, function() {
    echo "tick\n";
    swoole_event_exit();
});
Swoole\Event::wait();
?>
--EXPECT--
tick
