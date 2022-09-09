--TEST--
swoole_event: invalid resource
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Event;

$fp = curl_init();
Assert::false(Event::add($fp, function ($fp) {
    echo "SUCCESS\n";
}));
Assert::eq(swoole_last_error(), SWOOLE_ERROR_EVENT_SOCKET_INVALID);
Event::wait();
?>
--EXPECTF--
Warning: Swoole\Event::add(): fd argument must be either valid PHP stream or valid PHP socket resource in %s on line %d
