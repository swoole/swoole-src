--TEST--
swoole_coroutine: fgets
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";

go(function () {
    $file = __DIR__ . '/fgets.phpt';
    $fp = fopen($file, 'r');
    if (!$fp)
    {
        echo "ERROR\n";
        return;
    }

    $data = '';
    while (1)
    {
        $line = co::fgets($fp);
        if (empty($line) and feof($fp))
        {
            break;
        }
        $data .= $line;
//        echo $line;
    }
    assert(md5($data) == md5_file($file));
});

?>
--EXPECT--