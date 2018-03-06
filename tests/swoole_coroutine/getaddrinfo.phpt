--TEST--
swoole_coroutine: getaddrinfo
--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc"; ?>
--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";

use Swoole\Coroutine as co;

co::create(function () {
    $ip = co::getaddrinfo('www.baidu.com');
    assert(!empty($ip) and is_array($ip));
});
?>
--EXPECT--
