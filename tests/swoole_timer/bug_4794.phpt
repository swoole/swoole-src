--TEST--
swoole_timer: #4794 Timer::add() (ERRNO 505): msec value[0] is invalid
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;

run(function(){
    $channel = new Channel(1);
    go(function () use ($channel) {
        $channel->push(['rand' => 9999]);
    });
    go(function () use ($channel) {
        $data = $channel->pop(0.00001);
        var_dump($data);
    });
});
?>
--EXPECT--
array(1) {
  ["rand"]=>
  int(9999)
}
