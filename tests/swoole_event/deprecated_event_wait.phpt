--TEST--
swoole_event: deprecated_event_wait
--SKIPIF--
<?php

use SebastianBergmann\CodeCoverage\Report\PHP;

use function Swoole\Coroutine\run;

require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

error_reporting(E_ALL & E_DEPRECATED);

run(function () {
    throw new Exception("Error Processing Request", 1);
});

?>
--EXPECT--
