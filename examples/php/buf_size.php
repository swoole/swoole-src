<?php
$fds = [];

socket_create_pair(AF_UNIX, SOCK_DGRAM, 0, $fds);

$socket = $fds[0];

socket_set_option($socket, SOL_SOCKET, SO_SNDBUF, 8 * 1024 * 1024);
$send_buf_size = socket_get_option($socket, SOL_SOCKET, SO_SNDBUF);
echo "send_buf_size=$send_buf_size\n";


socket_set_option($socket, SOL_SOCKET, SO_RCVBUF, 8 * 1024);
$recv_buf_size = socket_get_option($socket, SOL_SOCKET, SO_RCVBUF);
echo "recv_buf_size=$recv_buf_size\n";

$n = $send_buf_size - 32;
$ret_n = socket_write($socket, str_repeat('A', $n), $n);
var_dump($ret_n);

$data = socket_read($fds[1], $n);
var_dump(strlen($data));
