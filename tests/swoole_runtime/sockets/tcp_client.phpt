--TEST--
swoole_runtime/sockets: concurrent TCP clients receive the TEST_DOMAIN_3 redirect
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_extension_not_exist('sockets');
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Coroutine\Socket;
use Swoole\Runtime;

use function Swoole\Coroutine\run;

const N = 8;

Runtime::enableCoroutine(SWOOLE_HOOK_ALL);
$completed = 0;
run(function () use (&$completed) {
    for ($i = 0; $i < N; $i++) {
        go(function () use (&$completed) {
            $domain = TEST_DOMAIN_3;
            $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
            if ($socket === false) {
                $error = socket_last_error();
                throw new RuntimeException("socket_create() failed: [{$error}] " . socket_strerror($error));
            }
            $check = function (bool $success, string $operation) use ($socket): void {
                if (!$success) {
                    $error = socket_last_error($socket);
                    throw new RuntimeException("{$operation} failed for " . TEST_DOMAIN_3
                        . ": [{$error}] " . socket_strerror($error));
                }
            };
            try {
                Assert::isInstanceOf($socket, Socket::class);
                $check(socket_connect($socket, $domain, 80), 'socket_connect()');
                $request = "GET / HTTP/1.0\r\nHost: {$domain}\r\nConnection: close\r\n\r\n";
                $offset = 0;
                while ($offset < strlen($request)) {
                    $written = socket_write($socket, substr($request, $offset));
                    $check($written !== false && $written > 0, 'socket_write()');
                    $offset += $written;
                }

                $response = '';
                while (true) {
                    $data = socket_read($socket, 8192);
                    $check($data !== false, 'socket_read()');
                    if ($data === '') {
                        break;
                    }
                    $response .= $data;
                }
                // The HTTP endpoint redirects to HTTPS and need not return an HTML body.
                Assert::contains($response, "\r\n\r\n");
                Assert::regex($response, '/^HTTP\/1\.[01] 3[0-9]{2} /');
                Assert::regex($response, '/^Location:[ \t]*https:\/\/' . preg_quote($domain, '/') . '\/\r?$/mi');
                $completed++;
            } finally {
                socket_close($socket);
            }
        });
    }
});
Assert::same($completed, N);
echo "Done\n";
?>
--EXPECT--
Done
