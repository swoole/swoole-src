--TEST--
swoole_timer: function alias about swoole_timer_list
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
$extension = new ReflectionExtension('swoole');
echo substr_count($extension, "Swoole\\Timer\\Iterator");
?>
--EXPECT--
3
