--TEST--
SSH2 channel writes wait for the current libssh2 I/O direction under backpressure
--SKIPIF--
<?php
require_once 'ssh2_skip.inc';
ssh2t_needs_auth();
skip('socket_import_stream() is required', !function_exists('socket_import_stream'));
?>
--FILE--
<?php
require __DIR__ . '/ssh2_test.inc';

Co\run(function (): void {
    $listener = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, 0);
    $listener->setOption(SOL_SOCKET, SO_RCVBUF, 4096);
    $listener->bind('127.0.0.1', 0);
    $listener->listen();
    $port = $listener->getsockname()['port'];
    $stallWrites = false;
    $stalled = false;

    // Relay the configured SSH fixture through a local TCP proxy. Pausing the proxy's
    // reads creates real write backpressure without suspending or modifying the SSH server.
    go(function () use ($listener, &$stallWrites, &$stalled): void {
        $downstream = $listener->accept();
        $listener->close();
        $upstream = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, 0);
        $upstream->setOption(SOL_SOCKET, SO_RCVTIMEO, ['sec' => 5, 'usec' => 0]);
        if (!$upstream->connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT)) {
            throw new RuntimeException('Failed to connect the SSH proxy.');
        }

        $relay = static function ($source, $destination, bool $clientToServer) use (&$stallWrites, &$stalled): void {
            try {
                while (($data = $source->recv()) !== false && $data !== '') {
                    if ($clientToServer && $stallWrites) {
                        $stallWrites = false;
                        $stalled = true;
                        Co::sleep(0.2);
                    }
                    if ($destination->sendAll($data) !== strlen($data)) {
                        break;
                    }
                }
            } finally {
                // Either EOF closes both sides and wakes the other relay coroutine.
                $source->close();
                $destination->close();
            }
        };
        go(static fn () => $relay($upstream, $downstream, false));
        $relay($downstream, $upstream, true);
    });

    $session = ssh2_connect('127.0.0.1', $port);
    if ($session === false || !ssh2t_auth($session)) {
        throw new RuntimeException('Failed to authenticate with the SSH fixture.');
    }

    // Read first so the next operation must change from waiting for input to waiting
    // for output. The remote command produces no more input until stdin is closed.
    $channel = ssh2_exec($session, 'printf "ready\n"; cat >/dev/null; printf "done\n"');
    if ($channel === false) {
        throw new RuntimeException('Failed to open the SSH channel.');
    }
    echo fgets($channel);
    $socket = socket_import_stream($channel);
    if ($socket === false || !socket_set_option($socket, SOL_SOCKET, SO_SNDBUF, 4096)) {
        throw new RuntimeException('Failed to limit the SSH send buffer.');
    }
    ssh2_set_timeout($session, 2);

    $stallWrites = true;
    $body = str_repeat('x', 65536);
    $written = @fwrite($channel, $body);
    var_dump($written === strlen($body));
    var_dump($stalled);

    ssh2_send_eof($channel);
    echo stream_get_contents($channel);
    unset($socket);
    fclose($channel);
    ssh2_disconnect($session);
});
?>
--EXPECT--
ready
bool(true)
bool(true)
done
