--TEST--
swoole_runtime: out of coroutine
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_TCP);

$out = file_get_contents('http://www.baidu.com/');
Assert::contains($out, 'About Baidu');
?>
--EXPECT--
