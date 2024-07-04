--TEST--
swoole_thread: info
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Thread;

$args = Thread::getArguments();
Assert::assert($args === null);
?>
--EXPECTF--
