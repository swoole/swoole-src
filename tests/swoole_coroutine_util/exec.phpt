--TEST--
swoole_coroutine_util: exec
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';

go(function () {
    $data = co::exec('md5sum ' . TEST_IMAGE);
    assert($data['code'] == 0);
    assert($data['signal'] == 0);
    assert(strstr($data['output'], ' ', true) === md5_file(TEST_IMAGE));
});

?>
--EXPECT--