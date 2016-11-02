<?php
$serv = new swoole_server("0.0.0.0", 9509);
$serv->set(array('worker_num' => 1));
$serv->on('workerStart', function($serv, $worker_id) {
        //if($worker_id == 0) $serv->addtimer(500);
});
$serv->on('connect', function ($serv, $fd, $from_id){
    $serv->array['fd'] = &strval($fd);
    echo "[#".posix_getpid()."]\tClient@[$fd:$from_id]: Connect.\n";
});
$serv->on('receive', function ($serv, $fd, $from_id, $data) {
    //echo "[#".posix_getpid()."]\tClient[$fd]: $data\n";
    $array = array('A', 'B', 'C', 'D', 'E', 'F', 'G');
    $data = '';
    $n_bytes = 0;
    for ($i = 0; $i < 10; $i++)
    {
        $_str = str_repeat($array[$i % 7], 4030) . "\n";
        //$serv->send($fd, $_str);
        $n_bytes += strlen($_str);
        $data .= $_str;
    }
    echo "send " . $n_bytes . " bytes\n";
    $serv->send( $serv->array['fd'], $data);
    $serv->close($fd);
});
$serv->on('close', function ($serv, $fd, $from_id) {
    echo "[#".posix_getpid()."]\tClient@[$fd:$from_id]: Close.\n";
});
$serv->start();

