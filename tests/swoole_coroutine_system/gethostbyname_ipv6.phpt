--TEST--
swoole_coroutine_system: gethostbyname for IPv6
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Swoole\Coroutine::create(function () {
    $ip = Swoole\Coroutine\System::gethostbyname('ipv6.google.com', AF_INET6);
    phpt_var_dump($ip);
    Assert::notEmpty($ip);
});

?>
--EXPECT--
