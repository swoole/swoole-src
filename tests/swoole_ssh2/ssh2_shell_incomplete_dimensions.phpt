--TEST--
ssh2_shell() rejects a width without a height
--SKIPIF--
<?php
if (!function_exists('ssh2_shell')) {
    echo 'skip SSH2 support is not enabled';
}
?>
--FILE--
<?php
var_dump(ssh2_shell(null, 'xterm', [], 80));
?>
--EXPECTF--
Warning: ssh2_shell(): width specified without height parameter in %s on line %d
bool(false)
