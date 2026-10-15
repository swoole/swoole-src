--TEST--
swoole_socket_coro: exported streams use independent descriptors and coroutine I/O
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
use Swoole\Coroutine\Socket;

function checkExport(bool $condition): void
{
    if (!$condition) {
        throw new RuntimeException('Export assertion failed');
    }
}

Swoole\Coroutine\run(function () {
    foreach (['socket', 'stream', 'unset', 'repeat', 'shutdown'] as $order) {
        $listener = new Socket(AF_INET, SOCK_STREAM, 0);
        checkExport($listener->bind('127.0.0.1', 0) && $listener->listen());
        $client = new Socket(AF_INET, SOCK_STREAM, 0);
        checkExport($client->connect('127.0.0.1', $listener->getsockname()['port']));
        $peer = $listener->accept();
        $listener->close();
        $peer->setOption(SOL_SOCKET, SO_RCVTIMEO, ['sec' => 1, 'usec' => 0]);
        $stream = $client->export();
        checkExport(is_resource($stream));
        stream_set_timeout($stream, 1);
        stream_set_read_buffer($stream, 0);

        // The producer runs only after fread() yields the coroutine.
        Swoole\Coroutine::create(function () use ($peer) {
            Swoole\Coroutine::sleep(0.01);
            checkExport($peer->sendAll('reply') === 5);
        });
        checkExport(fread($stream, 5) === 'reply');
        checkExport(fwrite($stream, 'first') === 5 && $peer->recvAll(5) === 'first');

        if ($order === 'shutdown') {
            // Explicit shutdown affects the connection even while both descriptors remain open.
            checkExport($client->shutdown(STREAM_SHUT_WR));
            checkExport(is_resource($stream) && $peer->recv(1) === '');
            fclose($stream);
            checkExport($client->close());
        } elseif ($order === 'stream') {
            fclose($stream);
            checkExport($client->sendAll('next') === 4 && $peer->recvAll(4) === 'next');
            checkExport($client->close());
        } else {
            if ($order === 'unset') {
                unset($client);
            } elseif ($order === 'repeat') {
                $other = $client->export();
                checkExport(is_resource($other) && $other !== $stream);
                fclose($stream);
                $stream = $other;
                checkExport($client->close());
            } else {
                checkExport($client->close());
                checkExport($client->isClosed() && $client->export() === false);
            }
            checkExport(fwrite($stream, 'next') === 4 && $peer->recvAll(4) === 'next');
            fclose($stream);
        }
        // Both descriptors are closed, even while the closed PHP objects remain referenced.
        checkExport($peer->recv(1) === '');
        $peer->close();
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
