--TEST--
swoole_coroutine_util: gethostbyname timeout
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine as co;

co::create(function () {
    $result = Co::gethostbyname("wwww.xxxx.cccn.xer", AF_INET, 0.005);
    assert($result == false);
    assert(swoole_last_error() == SWOOLE_ERROR_DNSLOOKUP_RESOLVE_TIMEOUT);
    co::sleep(0.1);
    echo "NEXT\n";
    $result = Co::gethostbyname("www.baidu.com", AF_INET, 0.5);
    assert($result != false);
});
swoole_event_wait();
?>
--EXPECT--
NEXT
