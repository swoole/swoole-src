--TEST--
swoole_coroutine: gethostbyname for IPv6
--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc"; ?>
--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";

use Swoole\Coroutine as co;

co::create(function () {
    $ip = co::gethostbyname('www.baidu.com', AF_INET6);
    echo $ip."\n";
});

?>
--EXPECT--
::1
