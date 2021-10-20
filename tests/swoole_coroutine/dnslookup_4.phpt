--TEST--
swoole_coroutine: bad dns server
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\System;
use function Swoole\Coroutine\run;

run(function () {
    Co::set(['dns_server' => '192.0.0.1:10053']);
    $host = Swoole\Coroutine::dnsLookup('www.baidu.com', 0.5);
    Assert::eq($host, false);
    Assert::eq(swoole_last_error(), SWOOLE_ERROR_DNSLOOKUP_RESOLVE_FAILED);
});
?>
--EXPECT--
