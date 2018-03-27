--TEST--
swoole_coroutine: gethostbyname for IPv6
--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc"; ?>
--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";

use Swoole\Coroutine as co;

co::create(function () {
    $ip = co::gethostbyname('ipv6.baidu.com', AF_INET6);
    assert(!empty($ip));
});

?>
--EXPECT--
