<?php
$chan = new Swoole\Channel(1024 * 256);
$n = 100000;
$bytes = 0;

if (pcntl_fork() > 0)
{
    echo "Father\n";
    for ($i = 0; $i < $n; $i++)
    {
        $data = str_repeat('A', rand(100, 200));
        if ($chan->push($data) === false)
        {
            echo "channel full\n";
            usleep(1000);
            $i--;
            continue;
        }
        $bytes += strlen($data);
//        echo "#$i\tpush ".strlen($data)." bytes\n";
    }

    echo "total push bytes: $bytes\n";
    var_dump($chan->stats());
}
else
{
    echo "Child\n";
    for ($i = 0; $i < $n; $i++)
    {
        $data = $chan->pop();
        if ($data === false)
        {
            echo "channel empty\n";
            usleep(1000);
            $i--;
            continue;
        }
        $bytes += strlen($data);
//        echo "#$i\tpop " . strlen($data) . " bytes\n";
    }
    echo "total pop bytes: $bytes\n";
    var_dump($chan->stats());
}

