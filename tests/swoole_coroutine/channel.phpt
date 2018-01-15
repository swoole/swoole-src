--TEST--
swoole_coroutine: coro channel
--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc"; ?>
--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";
require_once __DIR__ . "/../include/lib/curl.php";

use Swoole\Coroutine as co;

$chan = new co\Channel(1);

co::create(function () use ($chan) {
    for($i=0;$i<100000;$i++) {
        co::sleep(1.0);
        $chan->push(['rand' => rand(1000, 9999), 'index' => $i]);
        echo "$i\n";
    }
});

co::create(function () use ($chan) {
    while(1) {
        $data = $chan->pop();
        var_dump($data);
    }
});

swoole_event::wait();

?>
--EXPECT--
OK
