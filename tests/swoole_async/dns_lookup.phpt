--TEST--
swoole_async: swoole_async_dns_lookup

--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
swoole_async_dns_lookup("www.baidu.com", function($host, $ip) {
    assert(ip2long($ip));
    echo "SUCCESS";
});
swoole_event_wait();
?>
--EXPECT--
SUCCESS
