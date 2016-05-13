var net = require('net');

var server = net.createServer(function (socket) {
socket.write("Echo server\r\n");
socket.pipe(socket);
});

server.listen(7001, "127.0.0.1");
