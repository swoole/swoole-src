--TEST--
swoole_table: create 10,000 objects
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
for ($i = 0; $i < 10000; $i++) {
    $main = new Swoole\Table(1);
}
echo "DONE\n";
?>
--EXPECT--
DONE
