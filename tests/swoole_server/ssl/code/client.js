const tls = require('tls');

const options = {
	rejectUnauthorized: false,
};

var socket = tls.connect(process.argv[2], '127.0.0.1', options, () => {
	socket.write('GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n');
});

socket.setEncoding('utf8');
socket.on('data', (data) => {
  console.log(data);
});

socket.on('end', () => {
  console.log('Ended')
});