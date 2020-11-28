--TEST--
swoole_event: read stdin
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

error_reporting(E_ALL & E_DEPRECATED);

swoole_event_add(STDIN, function ($fp) {
    var_dump(fread($fp, 1024));
    swoole_event_del(STDIN);
});

swoole_timer_after(100, function () {
    swoole_event_del(STDIN);
    fclose(STDIN);
});

?>
--EXPECTF--
Deprecated: Swoole\Event::rshutdown(): Event::wait() in shutdown function is deprecated in Unknown on line 0
string(0) ""
