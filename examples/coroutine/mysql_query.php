<?php
use Swoole\Coroutine as co;
co::set(['trace_flags' => 1]);

co::create(function() {


    $function = new ReflectionFunction('title');

    $function->invoke();
    echo "invoke444\n";

});

function title() {
    echo "333invoke_________________________________\n";
    $tcpclient = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
    var_dump($tcpclient->connect('127.0.0.1', 9501, 1));

}

echo "111\n";


echo "222\n";
co::go();
