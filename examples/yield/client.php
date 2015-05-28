<?php
class ClientActor
{
    function connect($ip, $port)
    {
        $cli = new swoole_client(SWOOLE_SOCK_TCP); 
        Scheduler::add($cli);
        $cli->connect($ip, $port);
        yield Scheduler::wait();
    }
    
    function recv()
    {
        yield Scheduler::wait();
    }
    
    function send($data)
    {
        echo $data."\n";
    }
    
    function close()
    {
        echo "close\n";
    }
}

class Scheduler
{
    static function add($cli)
    {
        $cli->on('Error', 'Scheduler::onError');
        $cli->on('Connect', 'Scheduler::onConnect');
        $cli->on('Receive', 'Scheduler::onReceive');
        $cli->on('Close', 'Scheduler::onClose');
        echo "on\n"; 
    }
    
    static function wait()
    {
        while(1)
        {
            echo __FILE__;
            sleep(1);
            return "hello";
        }
    }
}


function test()
{
    $cli = new CoClient;
    $ret = $cli->connect('127.0.0.1', 9501);
    if ($ret)
    {
        $cli->send("hello world");
        $recv = $cli->recv();
        var_dump($recv);
    }
    $cli->close();
}

test();
