--TEST--
swoole_http_server_coro: verify client certificate with ssl_cafile
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_ssl();
skip_if_command_not_found('curl');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Http\Server;
use SwooleTest\ProcessManager;

$pm = new ProcessManager;

$pm->parentFunc = function () use ($pm) {
    try {
        $port = $pm->getFreePort();
        $url = "https://127.0.0.1:{$port}/";

        $command = sprintf(
            'curl --silent --insecure --max-time 10 %s',
            escapeshellarg($url),
        );
        Assert::same(shell_exec($command) ?: '', '');

        // client.crt is expired and is not signed by ca-cert.pem; either failure proves chain validation ran.
        $command = sprintf(
            'curl --silent --insecure --max-time 10 --cert %s --key %s %s',
            escapeshellarg(SSL_FILE_DIR . '/client.crt'),
            escapeshellarg(SSL_FILE_DIR . '/client.key'),
            escapeshellarg($url),
        );
        Assert::same(shell_exec($command) ?: '', '');

        $command = sprintf(
            'curl --silent --insecure --max-time 10 --cert %s --key %s %s',
            escapeshellarg(SSL_FILE_DIR . '/client-cert.pem'),
            escapeshellarg(SSL_FILE_DIR . '/client-key.pem'),
            escapeshellarg($url),
        );
        Assert::same(shell_exec($command), 'OK');
    } finally {
        $pm->kill();
    }
};

$pm->childFunc = function () use ($pm) {
    go(function () use ($pm) {
        $server = new Server('127.0.0.1', $pm->getFreePort(), true);
        $server->set([
            'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
            'ssl_key_file' => SSL_FILE_DIR . '/server.key',
            'ssl_verify_peer' => true,
            'ssl_cafile' => SSL_FILE_DIR . '/ca-cert.pem',
        ]);
        $server->handle('/', function ($request, $response) use ($server) {
            $response->end('OK');
            $server->shutdown();
        });
        $pm->wakeup();
        $server->start();
    });
    Swoole\Event::wait();
};

$pm->childFirst();
$pm->run();
echo "DONE\n";
?>
--EXPECTF--
[%s]	NOTICE	Socket::ssl_verify() (ERRNO %d): can not verify peer from fd#%d with error#%d: %s
DONE
