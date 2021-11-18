--TEST--
swoole_event: read stdin
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

error_reporting(E_ALL & E_DEPRECATED);

Swoole\Event::add(STDIN, function ($fp) {
    var_dump(fread($fp, 1024));
    Swoole\Event::del(STDIN);
});

Swoole\Timer::after(100, function () {
    Swoole\Event::del(STDIN);
    fclose(STDIN);
});

?>
--EXPECTF--
Deprecated: Swoole\Event::rshutdown(): Event::wait() in shutdown function is deprecated in Unknown on line 0
string(0) ""
