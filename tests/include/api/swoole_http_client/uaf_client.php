<?php

require_once __DIR__ . "/../../../include/bootstrap.php";

/*
require('net').createServer(swoole_function(socket) {
    socket.on('data', swoole_function(data) {
        socket.write('HTTP/1.1 200 OK\r\n');
        socket.write('Transfer-Encoding: chunked\r\n');
        socket.write('\r\n');

        var php_func = "hello"
        // var php_func = "ReflectionClass::export"

        socket.write('4\r\n');
        socket.write('func\r\n');
        socket.write('0\r\n');
        socket.write('\r\n');
        socket.write('HTTP/1.1 200 OK\r\n');
        socket.write('Transfer-Encoding: ' + php_func + '\r\n');
        socket.write('\r\n');
    });
}).listen(9090, '127.0.0.1');
 */


// 旧版本会因为因为 use after free
// 回调的zval 指向 parser header的zval
// 最后 call hello

function hello() {
    echo "=======================================\n";
    echo "call hello\n";
    var_dump(func_get_args());
}


$cli = new swoole_http_client("127.0.0.1", 9090);
$cli->get("/", function(swoole_http_client $cli) {
    echo "receive:", $cli->body, "\n";
});
