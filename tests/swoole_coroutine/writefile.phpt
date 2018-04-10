--TEST--
swoole_coroutine: Co::writeFile

--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";

$content = file_get_contents(TEST_IMAGE);
$filename = __DIR__ . '/tmp_file.jpg';
go(function () use ($filename, $content) {
    $n = Co::writeFile($filename, $content);
    assert(md5_file($filename) == md5_file(TEST_IMAGE));
    assert($n === filesize($filename));
    unlink($filename);
});
?>
--EXPECT--
