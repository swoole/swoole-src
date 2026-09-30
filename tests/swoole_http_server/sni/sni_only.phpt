--TEST--
swoole_http_server/sni: SNI certificates without a default certificate
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_no_ssl();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\Http\Server;

$pm = new ProcessManager;
$pm->setWaitTimeout(10);

$pm->parentFunc = function () use ($pm) {
    $port = $pm->getFreePort();
    $context = stream_context_create([
        'ssl' => [
            'capture_peer_cert' => true,
            'peer_name' => 'cs.php.net',
            'verify_peer' => false,
            'verify_peer_name' => false,
        ],
    ]);
    $client = stream_socket_client(
        "tls://127.0.0.1:$port",
        $errno,
        $errstr,
        1,
        STREAM_CLIENT_CONNECT,
        $context
    );
    Assert::resource($client);
    $certificate = stream_context_get_options($context)['ssl']['peer_certificate'];
    Assert::same(openssl_x509_parse($certificate)['subject']['CN'], 'cs.php.net');
    fwrite($client, "GET / HTTP/1.1\r\nHost: cs.php.net\r\nConnection: close\r\n\r\n");
    Assert::contains(stream_get_contents($client), 'HTTP/1.1 200 OK');
    fclose($client);

    $context = stream_context_create([
        'ssl' => [
            'SNI_enabled' => false,
            'verify_peer' => false,
            'verify_peer_name' => false,
        ],
    ]);
    Assert::false(@stream_socket_client(
        "tls://127.0.0.1:$port",
        $errno,
        $errstr,
        1,
        STREAM_CLIENT_CONNECT,
        $context
    ));

    $pm->kill();
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP | SWOOLE_SSL);
    $server->set([
        'log_file' => '/dev/null',
        'worker_num' => 1,
        'ssl_sni_certs' => [
            'cs.php.net' => [
                'ssl_cert_file' => SSL_FILE_DIR . '/sni_server_cs_cert.pem',
                'ssl_key_file' => SSL_FILE_DIR . '/sni_server_cs_key.pem',
            ],
        ],
    ]);
    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('request', function (Request $request, Response $response) {
        $response->end();
    });
    $server->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
