<?php
function BatchExecMethodByCo()
{
    $args = func_get_args();
    $channel = new \Swoole\Coroutine\Channel(count($args));
    foreach ($args as $key => $func) {
        go(function()use($channel,$func,$key){
            $res = $func();
            $channel->push([$key=>$res]);
        });
    }
    $list = [];
    go(function()use(&$list,$args,$channel){
        foreach ($args as $key => $chan) {
            $list[$key] = $channel->pop();
        }
    });
    swoole_event_wait();
    return $list;
}
function test($value='')
{
    \Co::sleep(1);
    return "test\n";
}
function test2($value='')
{
    \Co::sleep(1);
    return "test2 ".rand(1,10)."\n";
}
$r = BatchExecMethodByCo("test","test2","test");
var_dump($r);