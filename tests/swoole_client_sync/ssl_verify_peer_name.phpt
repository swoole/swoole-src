--TEST--
swoole_client_sync: verify the TLS peer against the connection target by default
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_ssl();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Client;
use Swoole\Server;
use SwooleTest\Assert;
use SwooleTest\ProcessManager;

$pm = new ProcessManager;
$pm->childFirst();
$pm->childFunc = static function () use ($pm) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP | SWOOLE_SSL);
    $server->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'ssl_cert_file' => SSL_FILE_DIR . 'server.crt',
        'ssl_key_file' => SSL_FILE_DIR . 'server.key',
    ]);
    $server->on('WorkerStart', static function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('Receive', static function () {});
    $server->start();
};
$pm->parentFunc = static function () use ($pm) {
    Co::set(['log_file' => TEST_LOG_FILE]);
    $settings = [
        'ssl_verify_peer' => true,
        'ssl_cafile' => SSL_FILE_DIR . 'ca.crt',
    ];
    foreach ([
        ['127.0.0.1', null, true],
        ['localhost', null, false],
        ['localhost', '', false],
        ['localhost', '127.0.0.1', true],
    ] as [$host, $name, $matches]) {
        $client = new Client(SWOOLE_SOCK_TCP | SWOOLE_SSL);
        $client->set($name === null ? $settings : $settings + ['ssl_host_name' => $name]);
        Assert::same(@$client->connect($host, $pm->getFreePort(), 3), $matches);
        if ($matches) {
            $client->close();
        } else {
            Assert::same($client->errCode, SWOOLE_ERROR_SSL_VERIFY_FAILED);
        }
    }

    $client = new Client(SWOOLE_SOCK_TCP);
    $client->set($settings);
    Assert::true($client->connect('localhost', $pm->getFreePort(), 3));
    Assert::false(@$client->enableSSL());
    Assert::same($client->errCode, SWOOLE_ERROR_SSL_VERIFY_FAILED);
    Assert::false($client->isConnected());
    $pm->kill();
};
$pm->run();
echo "DONE\n";
?>
--EXPECT--
DONE
