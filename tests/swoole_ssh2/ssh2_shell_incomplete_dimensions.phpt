--TEST--
ssh2_shell() rejects a width without a height
--SKIPIF--
<?php require_once 'ssh2_skip.inc'; ?>
--FILE--
<?php
ssh2_shell(null, 'xterm', [], 80);
?>
--EXPECTF--
Fatal error: ssh2_shell(): width specified without height parameter in %s on line %d
