--TEST--
swoole_coroutine_util: fread and fseek
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine as co;

co::create(function () {
    $fp = fopen(__FILE__, 'r');
    if ($fp) {
        fseek($fp, 1024);
        $php_data = fread($fp, fstat($fp)['size']);
        $co_data = co::fread($fp);
        Assert::same($php_data, $co_data);
    } else {
        echo "ERROR\n";
    }
});

swoole_event_wait();

?>
--EXPECT--
