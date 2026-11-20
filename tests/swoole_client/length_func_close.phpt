--TEST--
swoole_client: package_length_func closing the client during recv
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
    fwrite($conn, pack('N', 8) . 'abcd');
    usleep(300000);
    exit(0);
}

$client = new Swoole\Client(SWOOLE_SOCK_TCP);
$client->set([
    'open_length_check' => true,
    'package_length_type' => 'N',
    'package_length_offset' => 0,
    'package_body_offset' => 4,
    'package_length_func' => function ($data) use (&$client) {
        $client->close();
        return strlen($data) < 4 ? 0 : unpack('N', $data)[1];
    },
]);
$client->connect('127.0.0.1', $port, 2);
var_dump($client->recv());
pcntl_waitpid($pid, $status);
echo "DONE\n";
?>
--EXPECT--
bool(false)
DONE
