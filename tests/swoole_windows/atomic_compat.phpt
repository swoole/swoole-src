--TEST--
swoole_windows: use thread atomics through the common Atomic API
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
if (stripos(PHP_OS, 'WIN') !== 0) {
    die('skip Windows only');
}
if (!class_exists(Swoole\Thread\Atomic::class, false)) {
    die('skip thread atomic not available');
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$atomic = new Swoole\Atomic(1);
Assert::assert($atomic instanceof Swoole\Thread\Atomic);
Assert::same($atomic->add(2), 3);
Assert::same($atomic->sub(), 2);
Assert::assert($atomic->cmpset(2, 9));
Assert::same($atomic->get(), 9);
$atomic->set(4);
Assert::same($atomic->get(), 4);

$long = new Swoole\Atomic\Long(1 << 40);
Assert::assert($long instanceof Swoole\Thread\Atomic\Long);
Assert::same($long->add(2), (1 << 40) + 2);
Assert::same($long->sub(), (1 << 40) + 1);
Assert::assert($long->cmpset((1 << 40) + 1, 7));
Assert::same($long->get(), 7);
$long->set(3);
Assert::same($long->get(), 3);

echo "DONE\n";
?>
--EXPECT--
DONE
