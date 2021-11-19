--TEST--
swoole_runtime: stream context pass null
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Swoole\Runtime::enableCoroutine();
go(function() {
   //This function internal send null stream context parameter to `php_stream_open_wrapper_ex`
   $md5 = md5_file('https://www.baidu.com');
   var_dump(!empty($md5));
});
Swoole\Event::wait();

?>
--EXPECT--
bool(true)
