--TEST--
swoole_client_async: a file truncated during sendfile closes the connection
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Async\Client;

const FILE_SIZE = 16 * 1024 * 1024;

$file = tempnam(sys_get_temp_dir(), 'swoole-sendfile-truncated-');
file_put_contents($file, str_repeat('x', FILE_SIZE));

$pm             = new ProcessManager();
$pm->parentFunc = function () use ($pm, $file) {
    $client = new Client(SWOOLE_SOCK_TCP);
    $client->set(['socket_buffer_size' => 65536]);
    $client->on('connect', function (Client $client) use ($file) {
        Assert::true($client->sendfile($file));
    });
    $client->on('receive', function () {});
    $client->on('error', function () {
        echo "error\n";
    });
    $client->on('close', function () {
        echo "close\n";
    });
    $client->connect('127.0.0.1', $pm->getFreePort(), 1);
    Swoole\Event::wait();
};
$pm->childFunc = function () use ($pm, $file) {
    $server = stream_socket_server('tcp://127.0.0.1:' . $pm->getFreePort());
    $pm->wakeup();
    $conn = stream_socket_accept($server, 5);
    stream_set_timeout($conn, 5);

    // Data has arrived, so the transfer has started; truncate the file under it.
    $received = strlen(fread($conn, 65536));
    Assert::greaterThan($received, 0);
    $fp = fopen($file, 'r+');
    ftruncate($fp, 1024 * 1024);
    fclose($fp);

    $received += strlen(stream_get_contents($conn));
    Assert::false(stream_get_meta_data($conn)['timed_out']);
    Assert::lessThan($received, FILE_SIZE);
};
$pm->childFirst();
$pm->run();
$pm->expectExitCode(0);
unlink($file);
echo "DONE\n";
?>
--EXPECTF--
[%s]	WARNING	Socket::handle_sendfile() (ERRNO 502): sendfile(%s, %d, %d) reached the end of the file
close
DONE
