--TEST--
swoole_process_pool: construct twice
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Process\Pool;

$pool = new Pool(1);

try {
    $pool->__construct(1);
} catch (Error $e) {
    echo $e->getMessage() . PHP_EOL;
}
?>
--EXPECT--
Constructor of Swoole\Process\Pool can only be called once
