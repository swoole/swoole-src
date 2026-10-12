--TEST--
NameResolver: BASE server service_name survives worker reload and deregisters on shutdown
--SKIPIF--
<?php
if (!extension_loaded('swoole')) die('skip swoole required');
if (PHP_OS_FAMILY === 'Windows') die('skip process support required');
if (!ini_get('swoole.enable_library')) die('skip bundled library required');
?>
--FILE--
<?php
define('SERVER_MODE', SWOOLE_BASE);
require __DIR__ . '/name_resolver_lifecycle.inc';
?>
--EXPECT--
DONE
