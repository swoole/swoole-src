--TEST--
swoole_coroutine_util: gethostbyname
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine as co;

co::create(function () {
    $ip = co::gethostbyname('www.baidu.com');
    assert($ip != false);
});

?>
--EXPECT--