--TEST--
ssh2 wrappers release the parsed URL when it has no path
--SKIPIF--
<?php
require_once __DIR__ . '/../include/skipif.inc';
skip('SSH2 support is not enabled', !function_exists('ssh2_exec'));
?>
--FILE--
<?php
$before = memory_get_usage();
for ($i = 0; $i < 1000; $i++) {
    @file_exists('ssh2.sftp://1');
}
var_dump(memory_get_usage() - $before < 16384);
?>
--EXPECT--
bool(true)
