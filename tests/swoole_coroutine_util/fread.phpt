--TEST--
swoole_coroutine_util: fread
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine as co;

co::create(function () {
    $fp = fopen(TEST_IMAGE, 'r');
    if ($fp)
    {
        $data = co::fread($fp);
        Assert::same(md5($data), md5_file(TEST_IMAGE));
    }
    else
    {
        echo "ERROR\n";
    }
});

?>
--EXPECT--
