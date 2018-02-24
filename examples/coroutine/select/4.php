<?php
$c1 = new chan(3);

go(function () use ($c1) {
    $read_list = [$c1];
    $write_list = null;
    $result = chan::select($read_list, $write_list, 0.5);
    var_dump($result, $read_list, $write_list);
    echo "exit\n";
});

swoole_event::wait();
