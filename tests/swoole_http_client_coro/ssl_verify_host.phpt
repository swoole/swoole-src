--TEST--
swoole_http_client_coro: explicit host verification is independent of chain verification and preserves defaults
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_ssl();
?>
--FILE--
<?php
use Swoole\Coroutine;
use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\Http\Server;

Coroutine\run(function () {
    Coroutine::set(['log_level' => SWOOLE_LOG_NONE]);
    $server = new Server('127.0.0.1', 0, true);
    $server->set([
        'ssl_cert_file' => __DIR__ . '/../include/ssl_certs/curl-server.crt',
        'ssl_key_file' => __DIR__ . '/../include/ssl_certs/server.key',
    ]);
    $requests = 0;
    $server->handle('/', function ($request, $response) use (&$requests) {
        $requests++;
        $response->end('TLS');
    });
    Coroutine::create(fn () => $server->start());
    $ca = __DIR__ . '/../include/ssl_certs/ca.crt';
    try {
        foreach ([
            [['ssl_verify_peer' => false, 'ssl_host_name' => 'wrong.test'], true],
            [['ssl_verify_peer' => false, 'ssl_verify_host' => true, 'ssl_host_name' => 'wrong.test'], false],
            [['ssl_verify_peer' => false, 'ssl_verify_host' => true, 'ssl_host_name' => 'localhost'], true],
            [['ssl_verify_peer' => true, 'ssl_verify_host' => false, 'ssl_host_name' => 'wrong.test', 'ssl_cafile' => $ca], true],
            [['ssl_verify_peer' => true, 'ssl_host_name' => 'wrong.test', 'ssl_cafile' => $ca], false],
        ] as [$options, $success]) {
            $client = new Client('127.0.0.1', $server->port, true);
            $client->set($options + ['timeout' => 2]);
            $before = $requests;
            if (@$client->get('/') !== $success || $requests !== $before + (int) $success
                || ($success ? $client->body !== 'TLS' : $client->errCode !== SWOOLE_ERROR_SSL_VERIFY_FAILED)) {
                throw new RuntimeException('Unexpected verification policy: ' . var_export([$options, $client->errCode, $client->errMsg], true));
            }
            $client->close();
        }
    } finally {
        $server->shutdown();
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
