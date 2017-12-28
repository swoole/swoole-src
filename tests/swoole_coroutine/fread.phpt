--TEST--
swoole_coroutine: fread
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";

use Swoole\Coroutine as co;

co::create(function () {
    $fp = fopen(TEST_IMAGE, 'r');
    if ($fp)
    {
        $data = co::fread($fp);
        assert(md5($data) == md5_file(TEST_IMAGE));
    }
    else
    {
        echo "ERROR\n";
    }
});

?>
--EXPECT--