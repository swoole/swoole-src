var http = require('http');
http.createServer(function (req, res) {
    res.writeHead(200, {
        'Server': "node.js"}
    );
    res.end("<h1>Hello World</h2>");
}).listen(8080, '127.0.0.1');
console.log('Server running at http://127.0.0.1:8080/');
