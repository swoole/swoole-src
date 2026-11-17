--TEST--
swoole_client: package_length_func with a fragmented packet
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$server = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
$port = (int) explode(':', stream_socket_get_name($server, false))[1];

$pid = pcntl_fork();
if ($pid == 0) {
    $conn = stream_socket_accept($server, 5);
    // 4-byte big-endian total length, then the body
    $packet = pack('N', 100) . str_repeat('x', 96);
    stream_set_write_buffer($conn, 0);
    fwrite($conn, substr($packet, 0, 50));
    usleep(200000);
    fwrite($conn, substr($packet, 50));
    usleep(300000);
    exit(0);
}

$client = new Swoole\Client(SWOOLE_SOCK_TCP);
$client->set([
    'open_length_check' => true,
    'package_length_func' => function ($data) {
        return strlen($data) < 4 ? 0 : unpack('N', $data)[1];
    },
    'package_max_length' => 65536,
]);
$client->connect('127.0.0.1', $port, 5);
$data = $client->recv();
var_dump(strlen($data), $data === pack('N', 100) . str_repeat('x', 96));
pcntl_waitpid($pid, $status);
?>
--EXPECT--
int(100)
bool(true)
