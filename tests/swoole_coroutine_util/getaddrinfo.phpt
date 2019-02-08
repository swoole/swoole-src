--TEST--
swoole_coroutine_util: getaddrinfo
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $ip_list = Co::getaddrinfo('www.baidu.com', AF_INET);
    assert(!empty($ip_list) and is_array($ip_list));
    foreach ($ip_list as $ip) {
        assert(preg_match(IP_REGEX, $ip));
    }
    echo "DONE\n";
});
?>
--EXPECT--
DONE
