--TEST--
swoole_event: Swoole\Event::defer without io
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Swoole\Event::defer(function () {
    echo "defer [1]\n";
});

Swoole\Event::wait();
?>
--EXPECT--
defer [1]
