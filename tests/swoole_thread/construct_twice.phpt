--TEST--
swoole_thread: construct twice
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Thread;

$thread = new Thread(TESTS_API_PATH . '/swoole_thread/sleep.php');

try {
    $thread->__construct(TESTS_API_PATH . '/swoole_thread/sleep.php');
} catch (Error $e) {
    echo $e->getMessage() . PHP_EOL;
}

$thread->join();
?>
--EXPECT--
Constructor of Swoole\Thread can only be called once
