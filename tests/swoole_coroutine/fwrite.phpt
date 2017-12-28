--TEST--
swoole_coroutine: fwrite
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";

use Swoole\Coroutine as co;

co::create(function () {
    $file = __DIR__ . '/tmp';
    $fp = fopen($file, 'w+');
    $data = RandStr::gen(8192 * 8);
    if ($fp)
    {
        $ret = co::fwrite($fp, $data);
        if ($ret)
        {
            assert(md5($data) == md5_file($file));
            unlink($file);

            return;
        }
    }
    unlink($file);
    echo "ERROR\n";
});

?>
--EXPECT--