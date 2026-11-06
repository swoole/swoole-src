--TEST--
swoole_server: a file truncated during sendfile closes the connection
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_ssl();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

const FILE_SIZE = 16 * 1024 * 1024;

$file = tempnam(sys_get_temp_dir(), 'swoole-sendfile-truncated-');

foreach ([[SWOOLE_BASE, false], [SWOOLE_PROCESS, false], [SWOOLE_BASE, true]] as [$mode, $ssl]) {
    file_put_contents($file, str_repeat('x', FILE_SIZE));

    $pm             = new ProcessManager();
    $pm->parentFunc = function () use ($pm, $file, $ssl) {
        $client = new Swoole\Client(SWOOLE_SOCK_TCP | ($ssl ? SWOOLE_SSL : 0), SWOOLE_SOCK_SYNC);
        $client->set(['socket_buffer_size' => 65536]);
        Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 5));

        // Data has arrived, so the transfer has started; truncate the file under it.
        $received = strlen($client->recv(65536));
        Assert::greaterThan($received, 0);
        $fp = fopen($file, 'r+');
        ftruncate($fp, 1024 * 1024);
        fclose($fp);

        while (($data = $client->recv(65536)) !== '' && $data !== false) {
            $received += strlen($data);
        }
        Assert::same($data, '');
        Assert::lessThan($received, FILE_SIZE);
        $pm->kill();
    };
    $pm->childFunc = function () use ($pm, $file, $mode, $ssl) {
        $serv = new Swoole\Server('127.0.0.1', $pm->getFreePort(), $mode, SWOOLE_SOCK_TCP | ($ssl ? SWOOLE_SSL : 0));
        $serv->set([
            'worker_num'                     => 1,
            'log_file'                       => '/dev/null',
            'kernel_socket_send_buffer_size' => 65536,
            'ssl_cert_file'                  => SSL_FILE_DIR . '/server.crt',
            'ssl_key_file'                   => SSL_FILE_DIR . '/server.key',
        ]);
        $serv->on('workerStart', function () use ($pm) {
            $pm->wakeup();
        });
        $serv->on('connect', function (Swoole\Server $serv, $fd) use ($file) {
            Assert::true($serv->sendfile($fd, $file));
        });
        $serv->on('receive', function () {});
        $serv->start();
    };
    $pm->childFirst();
    $pm->run();
}

unlink($file);
echo "DONE\n";
?>
--EXPECT--
DONE
