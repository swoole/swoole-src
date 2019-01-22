<?php
function BatchExecMethodByCo($channel,$funcs)
{
    foreach ($funcs as $key => $func) {
        go(function()use($channel,$func,$key){
            $res = $func();
            $channel->push([$key=>$res]);
        });
    }    
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
go(function(){
    $c = 2;
    $channel = new \Swoole\Coroutine\Channel(2);
    $task = ["test","test2","test"];
    BatchExecMethodByCo($channel,$task);
    $list = [];
    $num = count($task);
    for ($i=0;$i<$num;$i++)
    {
        $list[$i] = $channel->pop();
    }
    var_dump($list);
});

