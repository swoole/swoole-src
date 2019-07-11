--TEST--
swoole_channel_coro: coro channel select timeout
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
exit("skip for select");
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine as co;

$chan = new co\Channel(1);

go(function () use ($chan) {
    $read_list = [$chan];
    $write_list = null;
    $result = chan::select($read_list, $write_list, 0.1);
    Assert::false($result);
});

swoole_event::wait();
?>
--EXPECT--
