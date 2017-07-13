<?php

// swoole_server
$s = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
socket_setopt($s, SOL_SOCKET, SO_REUSEADDR, 1);
socket_bind($s, "127.0.0.1", 9090);
socket_listen($s);

$func = "hello";

while($conn = socket_accept($s)) {
    socket_write($conn, "HTTP/1.1 200 OK\r\n\r\n");
    socket_write($conn, "HTTP/1.1 200 OK\r\nX-Func: {$func}\r\n\r\n");
    socket_close($conn);
}


// client
function hello() {
    echo "\n\nhello world!\n\n";
    swoole_event_exit();
    exit();
}

function req() {
    $cli = new swoole_http_client("127.0.0.1", 9090);
    $cli->on("close", function() {
        req();
    });
    $cli->get("/", function(swoole_http_client $cli) {
        echo "receive:", $cli->body, "\n";
    });
}

req();



