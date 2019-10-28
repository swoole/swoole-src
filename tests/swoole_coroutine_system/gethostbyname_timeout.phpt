--TEST--
swoole_coroutine_system: gethostbyname timeout
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Swoole\Coroutine::create(function () {
    $result = Swoole\Coroutine\System::gethostbyname("wwww.xxxx.cccn.xer" . time(), AF_INET, 0.001);
    Assert::eq($result, false);
    Assert::same(swoole_last_error(), SWOOLE_ERROR_DNSLOOKUP_RESOLVE_TIMEOUT);
    co::sleep(0.1);
    echo "NEXT\n";
    $result = Swoole\Coroutine\System::gethostbyname("www.github.com", AF_INET, 1);
    Assert::notEmpty($result);
});
swoole_event_wait();
?>
--EXPECT--
NEXT
