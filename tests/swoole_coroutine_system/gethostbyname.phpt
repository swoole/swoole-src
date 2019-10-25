--TEST--
swoole_coroutine_system: gethostbyname
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Swoole\Coroutine::create(function () {
    $ip = Swoole\Coroutine\System::gethostbyname('www.baidu.com');
    Assert::assert($ip != false);
});

?>
--EXPECT--
