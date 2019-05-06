--TEST--
swoole_coroutine_util: gethostbyname for IPv6
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine as co;

co::create(function () {
    $ip = co::gethostbyname('ipv6.baidu.com', AF_INET6);
    Assert::assert(!empty($ip));
});

?>
--EXPECT--
