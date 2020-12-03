--TEST--
swoole_http_server/sni: server
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\Http\Server;

$pm = new ProcessManager;
$pm->useConstantPorts = true;

$pm->parentFunc = function () use ($pm) {
    $flags = STREAM_CLIENT_CONNECT;
    $ctxArr = [
        'cafile' => __DIR__ . '/sni_server_ca.pem',
        'capture_peer_cert' => true,
        'verify_peer' => false,
    ];

    $port = $pm->getFreePort();
    $ctxArr['peer_name'] = 'cs.php.net';
    $ctx = stream_context_create(['ssl' => $ctxArr]);
    $client = stream_socket_client("tls://127.0.0.1:$port", $errno, $errstr, 1, $flags, $ctx);
    $cert = stream_context_get_options($ctx)['ssl']['peer_certificate'];
    var_dump(openssl_x509_parse($cert)['subject']['CN']);

    $ctxArr['peer_name'] = 'uk.php.net';
    $ctx = stream_context_create(['ssl' => $ctxArr]);
    $client = @stream_socket_client("tls://127.0.0.1:$port", $errno, $errstr, 1, $flags, $ctx);
    $cert = stream_context_get_options($ctx)['ssl']['peer_certificate'];
    var_dump(openssl_x509_parse($cert)['subject']['CN']);

    $ctxArr['peer_name'] = 'us.php.net';
    $ctx = stream_context_create(['ssl' => $ctxArr]);
    $client = @stream_socket_client("tls://127.0.0.1:$port", $errno, $errstr, 1, $flags, $ctx);
    $cert = stream_context_get_options($ctx)['ssl']['peer_certificate'];
    var_dump(openssl_x509_parse($cert)['subject']['CN']);

    $pm->kill();
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm) {
    $http = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP | SWOOLE_SSL);
    $http->set([
        'log_file' => '/dev/null',
        'ssl_cert_file' => SSL_FILE_DIR.'/server.crt',
        'ssl_key_file' => SSL_FILE_DIR.'/server.key',
        'ssl_protocols' => SWOOLE_SSL_TLSv1_2 | SWOOLE_SSL_TLSv1_3 | SWOOLE_SSL_TLSv1_1 | SWOOLE_SSL_SSLv2,
        'ssl_sni_certs' => [
            "cs.php.net" => [
                'ssl_cert_file' => SSL_FILE_DIR . "/sni_server_cs_cert.pem",
                'ssl_key_file' => SSL_FILE_DIR . "/sni_server_cs_key.pem"
            ],
            "uk.php.net" => [
                'ssl_cert_file' => SSL_FILE_DIR . "/sni_server_uk_cert.pem",
                'ssl_key_file' => SSL_FILE_DIR . "/sni_server_uk_key.pem"
            ],
            "us.php.net" => [
                'ssl_cert_file' => SSL_FILE_DIR . "/sni_server_us_cert.pem",
                'ssl_key_file' =>  SSL_FILE_DIR . "/sni_server_us_key.pem",
            ],
        ]
    ]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Request $request, Response $response) {
        $response->end("hello world");
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
string(%d) "cs.php.net"
string(%d) "uk.php.net"
string(%d) "us.php.net"
DONE
