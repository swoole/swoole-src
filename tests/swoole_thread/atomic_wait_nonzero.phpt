--TEST--
Swoole\Thread\Atomic: wait on a nonzero value other than one
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Thread\Atomic;

$atomic = new Atomic(2);
$start = microtime(true);

Assert::false($atomic->wait(3));
Assert::lessThan(microtime(true) - $start, 1.5);
Assert::eq($atomic->get(), 2);

echo "DONE\n";
?>
--EXPECT--
DONE
