<?php
$clients = array();

for($i=0; $i< 20; $i++)
{
    $client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC); //同步阻塞
    $ret = $client->connect('127.0.0.1', 9501, 0.5, 0);
    if(!$ret)
    {
        echo "Connect Server fail.errCode=".$client->errCode;
    }
    else
    {
    	$client->send("HELLO WORLD\n");
    	$clients[$client->sock] = $client;
    }
}

while (!empty($clients))
{
    $error = array();
    $read = array_values($clients);
    $write = [$read[1], $read[3], $read[9]];
    $n = swoole_client_poll($read, $write, $error, 0.6);
    if ($n > 0)
    {
        foreach ($read as $index => $c)
        {
            echo "Recv #{$c->sock}: " . $c->recv() . "\n";
            unset($clients[$c->sock]);
        }

        foreach ($write as $index => $c)
        {
            echo "Writable #{$c->sock}\n";
        }
    }
}
