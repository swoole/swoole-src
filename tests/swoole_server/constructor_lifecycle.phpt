--TEST--
swoole_server: constructor lifecycle does not poison later construction
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;

Co::set(['log_level' => SWOOLE_LOG_NONE]);

function open_fds(): ?array
{
    if (!is_dir('/proc/self/fd')) {
        return null;
    }

    $fds = scandir('/proc/self/fd');
    if ($fds === false) {
        return null;
    }

    return array_values(array_diff($fds, ['.', '..']));
}

function open_fd_count(): ?int
{
    $fds = open_fds();

    return $fds === null ? null : count($fds);
}

function open_non_socket_fd(): array
{
    $stream = fopen('/dev/null', 'r');
    Assert::notEmpty($stream);

    $fd = null;
    foreach (open_fds() as $candidate) {
        if (@readlink('/proc/self/fd/' . $candidate) === '/dev/null') {
            $fd = (int) $candidate;
            break;
        }
    }

    Assert::notNull($fd);

    return [$stream, $fd];
}

$listener = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
Assert::notEmpty($listener);

$port = (int) parse_url(stream_socket_get_name($listener, false), PHP_URL_PORT);
Assert::greaterThan($port, 0);

try {
    new Server('127.0.0.1', $port, SWOOLE_BASE);
    Assert::true(false);
} catch (Swoole\Exception $exception) {
    Assert::contains($exception->getMessage(), 'failed to listen server port');
}

$server = new Server('127.0.0.1', 0, SWOOLE_BASE);
Assert::isInstanceOf($server, Server::class);

unset($server);
gc_collect_cycles();

$server = new Server('127.0.0.1', 0, SWOOLE_BASE);
Assert::isInstanceOf($server, Server::class);

unset($server);
gc_collect_cycles();

$fd_count = open_fd_count();
if ($fd_count !== null) {
    for ($i = 0; $i < 3; $i++) {
        $server = new Server('127.0.0.1', 0, SWOOLE_BASE);
        unset($server);
        gc_collect_cycles();

        Assert::same(open_fd_count(), $fd_count);
    }

    [$stream, $fd] = open_non_socket_fd();

    try {
        putenv('LISTEN_PID=' . posix_getpid());
        putenv('LISTEN_FDS=1');
        putenv('LISTEN_FDS_START=' . $fd);

        try {
            new Server('SYSTEMD', 0, SWOOLE_BASE);
            Assert::true(false);
        } catch (Error $exception) {
            Assert::contains($exception->getMessage(), 'failed to add systemd socket');
        }
    } finally {
        putenv('LISTEN_PID');
        putenv('LISTEN_FDS');
        putenv('LISTEN_FDS_START');
        fclose($stream);
    }

    Assert::same(open_fd_count(), $fd_count);
}
?>
--EXPECT--
