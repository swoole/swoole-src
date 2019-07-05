--TEST--
swoole_coroutine_util: exec
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_command_not_found('md5sum');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function () {
    $data = co::exec('md5sum ' . TEST_IMAGE);
    Assert::eq($data['code'], 0);
    Assert::eq($data['signal'], 0);
    Assert::eq(strstr($data['output'], ' ', true), md5_file(TEST_IMAGE));
});

?>
--EXPECT--
