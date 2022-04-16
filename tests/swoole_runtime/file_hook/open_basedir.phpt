--TEST--
swoole_runtime/file_hook: support open_basedir config
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;

run(function() {
    ini_set("open_basedir","/tmp/:/tmp/tes");
    mkdir("/home/test/",0755);
    var_dump(mkdir("/tmp/test/",0755));
    var_dump(mkdir("/tmp/test1/",0755));
    var_dump(mkdir("/tmp/test/test",0755, true));
    rmdir("/tmp/test/test");
    rmdir("/tmp/test/");
    rmdir("/tmp/test1/");
});
?>
--EXPECTF--

Warning: mkdir(): open_basedir restriction in effect. File(%s) is not within the allowed path(s): (%s) in %s on line 7
bool(true)
bool(true)
bool(true)
