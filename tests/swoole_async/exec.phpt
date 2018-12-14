--TEST--
swoole_async: exec
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$data = swoole_async::exec('md5sum ' . TEST_IMAGE, function ($data, $status)
{
    assert($status['code'] == 0);
    assert($status['signal'] == 0);
    assert(strstr($data, ' ', true) === md5_file(TEST_IMAGE));
});

?>
--EXPECT--