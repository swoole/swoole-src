--TEST--
swoole_server/ssl: DTLS binds its listener before selecting an SNI certificate
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    $pm = new SwooleTest\ProcessManager();
    $pm->parentFunc = function () use ($pm) {
        foreach (['cs.php.net', 'unknown.example'] as $host) {
            $client = new Swoole\Client(SWOOLE_SOCK_UDP | SWOOLE_SSL);
            $client->set(['ssl_host_name' => $host]);
            Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 5));
            $cert = $host === 'cs.php.net' ? 'sni_server_cs_cert.pem' : 'server.crt';
            Assert::same(trim($client->getPeerCert()), trim(file_get_contents(SSL_FILE_DIR . '/' . $cert)));
            Assert::same($client->send('ping'), 4);
            Assert::same($client->recv(), 'ping');
            $client->close();
        }
        $pm->kill();
    };
    $pm->childFunc = function () use ($pm, $mode) {
        $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), $mode, SWOOLE_SOCK_UDP | SWOOLE_SSL);
        $server->set([
            'worker_num' => 1,
            'reactor_num' => 1,
            'log_file' => '/dev/null',
            'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
            'ssl_key_file' => SSL_FILE_DIR . '/server.key',
            'ssl_sni_certs' => [
                'cs.php.net' => [
                    'ssl_cert_file' => SSL_FILE_DIR . '/sni_server_cs_cert.pem',
                    'ssl_key_file' => SSL_FILE_DIR . '/sni_server_cs_key.pem',
                ],
            ],
        ]);
        $server->on('workerStart', function () use ($pm) { $pm->wakeup(); });
        $server->on('receive', function ($server, $fd, $reactor, $data) { $server->send($fd, $data); });
        $server->on('packet', function () { Assert::true(false, 'DTLS uses onReceive'); });
        $server->start();
    };
    $pm->childFirst();
    $pm->run();
}
echo "DONE\n";
?>
--EXPECT--
DONE
