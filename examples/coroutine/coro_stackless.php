<?php
use Swoole\Coroutine as co;
//co::set(['trace_flags' => 1]);

co::create(
function() {
	$client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
	$res = $client->connect('127.0.0.1', 9501, 10);
    var_dump($res);
}
);
echo "111\n";
swoole_event_wait();
