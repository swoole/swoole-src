--TEST--
swoole_coroutine: gethostbyname
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function () {
    $ip1 = co::gethostbyname('www.baidu.com');
    assert(!empty($ip1));
    assert($ip1 == co::gethostbyname('www.baidu.com'));
    swoole_clear_dns_cache();
    $ip2 = co::gethostbyname('www.baidu.com');
    assert(!empty($ip2));

    for ($i = MAX_REQUESTS; $i--;) {
        go(function() {
            assert(!empty(co::gethostbyname('www.baidu.com')));
        });
    }
});
?>
--EXPECTF--
