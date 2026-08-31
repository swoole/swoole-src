--TEST--
swoole_http_server: ssl client ca
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;

$html = base64_encode(random_bytes(rand(2048, 65536)));

$pm->parentFunc = function ($pid) use ($pm, $html) {
    $stderr1 = tempnam('/tmp', 'swoole_client_ca_');
    $stderr2 = tempnam('/tmp', 'swoole_client_ca_');
    try {
        $url = "https://127.0.0.1:{$pm->getFreePort()}";
        $command = sprintf(
            'curl --silent --show-error --insecure --max-time 10 --stderr %s %s',
            escapeshellarg($stderr1),
            escapeshellarg($url),
        );
        Assert::same(shell_exec($command) ?: '', '');

        $command = sprintf(
            'curl --silent --show-error --insecure --max-time 10 --cert %s --key %s --stderr %s %s',
            escapeshellarg(SSL_FILE_DIR . '/client-cert.pem'),
            escapeshellarg(SSL_FILE_DIR . '/client-key.pem'),
            escapeshellarg($stderr2),
            escapeshellarg($url),
        );
        Assert::same(shell_exec($command), $html);
    } finally {
        unlink($stderr1);
        unlink($stderr2);
        $pm->kill();
    }
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm, $html) {
    $serv = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM, SWOOLE_SOCK_TCP | SWOOLE_SSL);
    $serv->set([
        'log_file' => '/dev/null',
        'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
        'ssl_key_file' => SSL_FILE_DIR . '/server.key',
        'ssl_verify_peer' => true,
        'ssl_verify_depth' => 10,
        'ssl_cafile' => SSL_FILE_DIR . '/ca-cert.pem',
    ]);
    $serv->on("workerStart", function ($serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('request', function ($req, $resp) use ($html) {
        $resp->end($html);
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
