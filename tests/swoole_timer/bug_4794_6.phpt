--TEST--
swoole_timer: #4794 Timer::add() (ERRNO 505): msec value[0] is invalid
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $ip_list = Swoole\Coroutine\System::getaddrinfo('www.baidu.com', AF_INET, SOCK_STREAM, STREAM_IPPROTO_TCP, null, 0.0002);
    Assert::assert(!empty($ip_list) and is_array($ip_list));
    foreach ($ip_list as $ip) {
        Assert::assert(preg_match(IP_REGEX, $ip));
    }
    echo "DONE\n";
});
?>
--EXPECT--
DONE
