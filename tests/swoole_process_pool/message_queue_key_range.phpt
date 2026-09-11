--TEST--
swoole_process_pool: reject message queue keys outside key_t
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_not_linux();
skip('64-bit only', PHP_INT_SIZE < 8);
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

try {
    new Swoole\Process\Pool(1, SWOOLE_IPC_MSGQUEUE, 1 << 32);
} catch (Swoole\Exception $exception) {
    echo $exception->getMessage(), PHP_EOL;
}
?>
--EXPECT--
the parameter $msgqueue_key is out of range
