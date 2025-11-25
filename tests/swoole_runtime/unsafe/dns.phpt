--TEST--
swoole_runtime/unsafe: dns
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc';
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use function Swoole\Coroutine\run;

run(function ()  {
    dns_check_record('www.baidu.com', DNS_A);
});
?>
--EXPECTF--
Warning: dns_check_record() has been disabled for security reasons in %s on line %d
