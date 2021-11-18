--TEST--
swoole_event: Swoole\Event::exit
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--

<?php
require __DIR__ . '/../include/bootstrap.php';

Swoole\Timer::tick(1, function() {
    echo "tick\n";
    Swoole\Event::exit();
});
Swoole\Event::wait();
?>
--EXPECT--
tick
