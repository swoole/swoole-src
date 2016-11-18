<?php
$chan = new Swoole\Channel(1024 * 256);
$n = 1000;
echo "start\n";

$bytes = 0;

for ($i = 0; $i < $n; $i++)
{
    $data = str_repeat('A', rand(100, 200));
    $chan->push($data);
    $bytes += strlen($data);
    echo "#$i\tpush ".strlen($data)." bytes\n";
}

echo "total push bytes: $bytes\n";
var_dump($chan->stats());

$bytes = 0;
for ($i = 0; $i < $n; $i++)
{
    $data = $chan->pop();
    $bytes += strlen($data);
    echo "#$i\tpop ".strlen($data)." bytes\n";
}
echo "total pop bytes: $bytes\n";
var_dump($chan->stats());

echo "end\n";