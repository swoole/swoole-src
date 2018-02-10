<?php
$c1 = new chan(3);
$c2 = new chan(2);

$c3 = new chan(2);
$c4 = new chan(2);

$c3->push(3);
$c3->push(3.1415);

$c4->push(3);
$c4->push(3.1415);

go(function () use ($c1, $c2, $c3, $c4) {
    echo "select\n";
    for ($i = 0; $i < 1; $i++)
    {
        $read_list = [$c1, $c2];
        $write_list = [$c3, $c4];
        $result = chan::select($read_list, $write_list, 5);
        var_dump($result, $read_list, $write_list);

        foreach($read_list as $ch)
        {
            var_dump($ch->pop());
        }

        foreach($write_list as $ch)
        {
            var_dump($ch->push(666));
        }
        echo "exit\n";
    }
});

go(function () use ($c3, $c4) {
    echo "producer\n";
    co::sleep(1);
    $data = $c3->pop();
    echo "pop[1]\n";
    var_dump($data);
});

swoole_event::wait();
