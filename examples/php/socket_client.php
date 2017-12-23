<?php
pcntl_signal(SIGIO, function () {
    echo "SIGIO";
});


$socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
socket_connect($socket, '127.0.0.1', 8889);

$timeout = array('sec'=>1, 'usec' => 500000);
socket_set_option($socket,SOL_SOCKET,SO_RCVTIMEO,$timeout);

$n = socket_recv($socket, $buf, 2048, MSG_WAITALL);

var_dump($n, $buf);
