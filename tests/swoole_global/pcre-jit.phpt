--TEST--
swoole_global: disable pcre jit
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_php_version_lower_than('7.3');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
assert(!ini_get('pcre.jit'));
?>
DONE
--EXPECT--
DONE
