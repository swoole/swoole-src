--TEST--
swoole_coroutine_util: getaddrinfo
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine as co;

co::create(function () {
    $ip = co::getaddrinfo('www.baidu.com');
    assert(!empty($ip) and is_array($ip));
});
?>
--EXPECT--
