--TEST--
swoole_coroutine_wait_group: empty
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$wg = new Swoole\Coroutine\WaitGroup;
$wg->add(1);
$wg->add(-1);
$wg->wait();
$wg->add(1);
$wg->done();
$wg->wait();
echo "DONE\n";
?>
--EXPECT--
DONE
