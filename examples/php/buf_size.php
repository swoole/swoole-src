<?php
$fds = [];

socket_create_pair(AF_UNIX, SOCK_DGRAM, 0, $fds);

$socket = $fds[0];

socket_set_option($socket, SOL_SOCKET, SO_SNDBUF, 8 * 1024 * 1024);
$retval = socket_get_option($socket, SOL_SOCKET, SO_SNDBUF);
var_dump($retval);

$n = $retval - 32;
$ret_n = socket_write($socket, str_repeat('A', $n), $n);
var_dump($ret_n);