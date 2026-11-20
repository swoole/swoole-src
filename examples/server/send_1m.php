<?php
// Send a large chunk of data to each client that connects.
$serv = new Swoole\Server('0.0.0.0', 9509);
$serv->set(['worker_num' => 1]);
$serv->on('connect', function ($serv, $fd, $reactor_id) {
    $serv->array['fd'] = strval($fd);
    echo '[' . posix_getpid() . '] Client@[' . $fd . ':' . $reactor_id . ']: Connect.' . PHP_EOL;
});
$serv->on('receive', function ($serv, $fd, $reactor_id, $data) {
    $array = ['A', 'B', 'C', 'D', 'E', 'F', 'G'];
    $data = '';
    $n_bytes = 0;
    for ($i = 0; $i < 10; $i++) {
        $_str = str_repeat($array[$i % 7], 4030) . PHP_EOL;
        $n_bytes += strlen($_str);
        $data .= $_str;
    }
    echo 'send ' . $n_bytes . ' bytes' . PHP_EOL;
    $serv->send($serv->array['fd'], $data);
    $serv->close($fd);
});
$serv->on('close', function ($serv, $fd, $reactor_id) {
    echo '[' . posix_getpid() . '] Client@[' . $fd . ':' . $reactor_id . ']: Close.' . PHP_EOL;
});
$serv->start();
