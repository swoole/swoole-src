--TEST--
swoole_timer: clear timer not exist
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Swoole\Timer::after(10, function () {
    assert(0); // never here
});
for ($n = MAX_REQUESTS; $n--;) {
    assert(Swoole\Timer::clear($n) === ($n === 1 ? true : false));
}
Swoole\Event::wait();
echo "DONE\n";
?>
--EXPECT--
DONE
