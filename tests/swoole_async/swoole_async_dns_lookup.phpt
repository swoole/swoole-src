--TEST--
swoole_async: swoole_async_dns_lookup

--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
swoole_async_dns_lookup("www.baidu.com", function($host, $ip) {
    assert(ip2long($ip));
    echo "SUCCESS";
});
swoole_event_wait();
?>

--EXPECT--
SUCCESS
