--TEST--
swoole_server: systemd fds
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_not_linux();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Client;
use Swoole\Server;

define('UNIX_SOCK_1', sys_get_temp_dir() . '/swoole-systemd-' . getmypid() . '-stream.sock');
define('UNIX_SOCK_2', sys_get_temp_dir() . '/swoole-systemd-' . getmypid() . '-dgram.sock');
define('HAVE_IPV6', boolval(@stream_socket_server('tcp://[::1]:0')));

register_shutdown_function(function () {
    if (file_exists(UNIX_SOCK_1)) {
        unlink(UNIX_SOCK_1);
    }
    if (file_exists(UNIX_SOCK_2)) {
        unlink(UNIX_SOCK_2);
    }
});

$pm = new SwooleTest\ProcessManager();
$pm->initFreePorts(2);
if (HAVE_IPV6) {
    $pm->initFreeIPv6Ports(2);
}
$pm->parentFunc = function ($pid) use ($pm) {
    $test_func = function ($type, $host, $port = 0) {
        $client = new Client($type);
        Assert::notEmpty($client->connect($host, $port));
        $client->send('SUCCESS');
        Assert::eq($client->recv(), 'SUCCESS' . PHP_EOL);
        $client->close();
    };

    $test_func(SWOOLE_SOCK_TCP, '127.0.0.1', $pm->getFreePort(0));
    $test_func(SWOOLE_SOCK_UDP, '127.0.0.1', $pm->getFreePort(1));

    if (HAVE_IPV6) {
        $test_func(SWOOLE_SOCK_TCP6, '::1', $pm->getFreePort(2));
        $test_func(SWOOLE_SOCK_UDP6, '::1', $pm->getFreePort(3));
    }

    $test_func(SWOOLE_SOCK_UNIX_STREAM, UNIX_SOCK_1);
    $test_func(SWOOLE_SOCK_UNIX_DGRAM, UNIX_SOCK_2);

    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    // Native streams must be used here: coroutine sockets create an event loop before Server::start().
    $sockets = [];
    $sockets[] = stream_socket_server('tcp://127.0.0.1:' . $pm->getFreePort(0), $errno, $errstr);
    $sockets[] = stream_socket_server('udp://127.0.0.1:' . $pm->getFreePort(1), $errno, $errstr, STREAM_SERVER_BIND);
    if (HAVE_IPV6) {
        $sockets[] = stream_socket_server('tcp://[::1]:' . $pm->getFreePort(2), $errno, $errstr);
        $sockets[] = stream_socket_server('udp://[::1]:' . $pm->getFreePort(3), $errno, $errstr, STREAM_SERVER_BIND);
    }
    $sockets[] = stream_socket_server('unix://' . UNIX_SOCK_1, $errno, $errstr);
    $sockets[] = stream_socket_server('udg://' . UNIX_SOCK_2, $errno, $errstr, STREAM_SERVER_BIND);

    // Find the first socket by inode; the temporary /proc directory descriptor is not a socket.
    // Use the child PID explicitly because PHP may have cached /proc/self before fork.
    $fd_directory = '/proc/' . posix_getpid() . '/fd';
    $target = 'socket:[' . fstat($sockets[0])['ino'] . ']';
    $start_fd = null;
    foreach (scandir($fd_directory) as $fd) {
        if (ctype_digit($fd) && @readlink($fd_directory . '/' . $fd) === $target) {
            $start_fd = (int) $fd;
            break;
        }
    }
    Assert::notNull($start_fd);
    foreach ($sockets as $i => $socket) {
        Assert::same(readlink($fd_directory . '/' . ($start_fd + $i)), 'socket:[' . fstat($socket)['ino'] . ']');
    }
    putenv('LISTEN_FDS_START=' . $start_fd);

    putenv('LISTEN_FDS=' . count($sockets));
    foreach ([null, posix_getppid()] as $owner) {
        putenv($owner === null ? 'LISTEN_PID' : 'LISTEN_PID=' . $owner);
        try {
            new Server('SYSTEMD', 0, SWOOLE_BASE);
            Assert::true(false);
        } catch (Error $exception) {
            Assert::contains($exception->getMessage(), 'failed to add systemd socket');
        }
        Assert::same(readlink($fd_directory . '/' . $start_fd), $target);
    }
    putenv('LISTEN_PID=' . posix_getpid());

    $serv = new Server('SYSTEMD', 0, SWOOLE_BASE);

    $serv->set(['worker_num' => 1, 'log_file' => '/dev/null']);
    $serv->on('WorkerStart', function (Server $serv) use ($pm) {
        $pm->wakeup();
    });

    $serv->on('packet', function (Server $serv, $data, $addr) {
        // var_dump($addr);
        $serv->sendto($addr['address'], $addr['port'] ?? 0, 'SUCCESS' . PHP_EOL);
    });

    $serv->on('receive', function (Server $serv, $fd, $tid, $data) {
        $serv->send($fd, 'SUCCESS' . PHP_EOL);
    });

    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
