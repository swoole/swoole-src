<?php
$c1 = new chan(0);
$c2 = new chan(0);

go(function () use ($c1, $c2, $c3, $c4) {
    echo "select\n";
    for ($i = 0; $i < 2; $i++)
    {
        $read_list = [$c1, $c2];
        $write_list = null;
        $result = chan::select($read_list, $write_list, 5);
        var_dump($result, $read_list, $write_list);

        foreach($read_list as $ch)
        {
            var_dump($ch->pop());
        }
    }
});


go(function () use ($c1, $c2) {
    echo "push start\n";
    co::sleep(1);
    $c1->push("resume");
    $c2->push("hello");
    echo "push end\n";
});

swoole_event::wait();
