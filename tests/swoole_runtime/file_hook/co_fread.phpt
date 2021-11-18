--TEST--
swoole_runtime/file_hook: fread
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

Swoole\Runtime::enableCoroutine();

go(function () {
    $fp = fopen(__FILE__, 'r');
    echo "open\n";
    $data = Co::fread($fp, 1024);
    echo "read\n";
    Swoole\Runtime::enableCoroutine(false);
    Assert::assert(!empty($data));
    Assert::same(md5($data), md5_file(__FILE__));
});

Swoole\Event::wait();
?>
--EXPECT--
open
read
