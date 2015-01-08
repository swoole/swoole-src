<?php
$fp = stream_socket_client("tcp://172.16.51.114:8000", $errno, $errstr, 30);
if (!$fp) {
    echo "$errstr ($errno)<br />\n";
} else {
    fwrite($fp, "GET / HTTP/1.0\r\nHost: www.example.com\r\nAccept: */*\r\n\r\n");
    sleep(1000);
    fclose($fp);
}
