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
    go(function () use ($pm, $html) {
        $commnd = "curl https://127.0.0.1:" . $pm->getFreePort() . " --cert " . SSL_FILE_DIR. "/client.crt" .
        " --key ". SSL_FILE_DIR. "/client.key -k -vvv --stderr /tmp/client_ca.txt";
        $out = shell_exec($commnd);
        Assert::eq($out, $html);
        $pm->kill();
    });
    Swoole\Event::wait();
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
        'ssl_cafile' => SSL_FILE_DIR . '/ca.crt',
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
