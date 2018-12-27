--TEST--
swoole_coroutine: gethostbyname
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function () {
    $ip1 = co::gethostbyname('www.baidu.com');
    swoole_clear_dns_cache();
    $ip = co::gethostbyname('www.baidu.com');
    assert($ip1 != $ip);

    for ($i = MAX_REQUESTS; $i--;) {
        assert($ip == co::gethostbyname('www.baidu.com'));
    }
});
?>
--EXPECTF--
