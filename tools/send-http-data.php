#!/usr/bin/env php
<?php
if ($argc < 3)  {
    exit("Usage: php send-http-data.php {port} {file} {:save}\n");
}

$port = intval($argv[1]);
$file = $argv[2];


$sock = stream_socket_client("tcp://127.0.0.1:{$port}");
fwrite($sock, file_get_contents($file));
stream_set_chunk_size($sock, 2*1024*1024);
$data = fread($sock, 8192 * 128);

if ($argc == 4 and $argv[3] == 'save')
{
    file_put_contents("resp.html", $data);
}
else
{
    echo $data;
}
