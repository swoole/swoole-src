--TEST--
swoole_event: swoole_event_defer without io
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

swoole_event_defer(function () {
    echo "defer [1]\n";
});

swoole_event_wait();
?>
--EXPECT--
defer [1]
