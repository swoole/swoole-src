--TEST--
swoole_coroutine_system: gethostbyname for IPv6
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
if (getenv("SKIP_ONLINE_TESTS")) {
    die("skip online test");
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Swoole\Coroutine::create(function () {
    $ip = Swoole\Coroutine\System::gethostbyname('ipv6.baidu.com', AF_INET6);
    Assert::assert(!empty($ip));
});

?>
--EXPECT--
