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
    if ($fp)
    {
        fseek($fp, 1024);
        $data = co::fread($fp);
        var_dump($data);
        assert(md5($data) == md5_file(TEST_IMAGE));
    }
    else
    {
        echo "ERROR\n";
    }
});

?>
--EXPECT--