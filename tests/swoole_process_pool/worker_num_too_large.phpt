--TEST--
swoole_process_pool: an oversized worker_num is rejected without aborting
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

try {
    new Swoole\Process\Pool(1000000);
} catch (Swoole\Exception $e) {
    echo "REJECTED\n";
}
echo "DONE\n";
?>
--EXPECTF--
%A
REJECTED
DONE
