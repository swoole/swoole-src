--TEST--
swoole_socket_coro: ssl client
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_no_ssl();
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http_test_cases.php';

use function Swoole\Coroutine\run;

run(function () {
    $content = http_get_with_co_socket('www.baidu.com');
    Assert::assert(strpos($content, 'map.baidu.com') !== false);
});
?>
--EXPECT--
