<?php

$sock = stream_socket_client('tcp://127.0.0.1:9501');
fwrite($sock, file_get_contents('httpdata'));
stream_set_chunk_size($sock, 2 * 1024 * 1024);
$data = fread($sock, 8192 * 128);
if ('save' == $argv[1]) {
    file_put_contents('resp.html', $data);
} else {
    echo $data;
}
