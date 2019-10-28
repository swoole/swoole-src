--TEST--
swoole_coroutine_system: gethostbyname
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Swoole\Coroutine::create(function () {
    $ip = Swoole\Coroutine\System::gethostbyname('www.baidu.com');
    Assert::assert($ip != false);
});

?>
--EXPECT--
