--TEST--
swoole_server: Server::sendfile delete_file ownership boundaries
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_in_valgrind();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Client;
use Swoole\Coroutine\System;
use Swoole\Runtime;
use Swoole\Server;

const CONTENT_SIZE = 256 * 1024;

$wait_gone = function (string $path): bool {
    for ($i = 0; $i < 200; $i++) {
        clearstatcache(true, $path);
        if (!is_file($path)) {
            return true;
        }
        System::sleep(0.025);
    }
    return false;
};

$transfer_path = tempnam('/tmp', 'swoole_srv_sendfile_transfer_');
$negative_path = tempnam('/tmp', 'swoole_srv_sendfile_negative_');
$stale_path    = tempnam('/tmp', 'swoole_srv_sendfile_stale_');
$content       = get_safe_random(CONTENT_SIZE);
file_put_contents($transfer_path, $content);
file_put_contents($negative_path, 'keep me');
file_put_contents($stale_path, 'delete me');

$pm             = new ProcessManager();
$pm->parentFunc = function () use ($pm, $transfer_path, $negative_path, $stale_path, $content, $wait_gone) {
    Runtime::enableCoroutine(SWOOLE_HOOK_ALL);
    Co\run(function () use ($pm, $transfer_path, $negative_path, $stale_path, $content, $wait_gone) {
        $client = new Client(SWOOLE_SOCK_TCP);
        Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 5));

        // A successful opted-in transfer sends the exact body and deletes at completion.
        $client->send("transfer\n");
        $received = '';
        while (strlen($received) < CONTENT_SIZE) {
            $chunk = $client->recv();
            if ($chunk === '' || $chunk === false) {
                break;
            }
            $received .= $chunk;
        }
        Assert::same($received, $content);
        Assert::true($wait_gone($transfer_path));

        // A negative session id is rejected before ownership, so the file is preserved.
        $client->send("negative\n");
        Assert::same(rtrim($client->recv()), 'negative-done');
        clearstatcache(true, $negative_path);
        Assert::true(is_file($negative_path));

        // A positive session id with no live connection passes pre-factory validation, so
        // ownership has moved and the later live-session rejection still deletes the file.
        $client->send("stale\n");
        Assert::same(rtrim($client->recv()), 'stale-done');
        Assert::true($wait_gone($stale_path));

        $client->close();
    });
    $pm->kill();
    @unlink($transfer_path);
    @unlink($negative_path);
    @unlink($stale_path);
};
$pm->childFunc = function () use ($pm, $transfer_path, $negative_path, $stale_path) {
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $serv->set([
        'worker_num'     => 1,
        'log_file'       => '/dev/null',
        'open_eof_check' => true,
        'package_eof'    => "\n",
    ]);
    $serv->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $serv->on('receive', function (Server $serv, $fd, $rid, $data) use ($transfer_path, $negative_path, $stale_path) {
        switch (rtrim($data)) {
            case 'transfer':
                $serv->sendfile($fd, $transfer_path, 0, 0, true);
                break;
            case 'negative':
                Assert::false(@$serv->sendfile(-1, $negative_path, 0, 0, true));
                $serv->send($fd, "negative-done\n");
                break;
            case 'stale':
                Assert::false($serv->sendfile($fd + 100000, $stale_path, 0, 0, true));
                $serv->send($fd, "stale-done\n");
                break;
        }
    });
    $serv->start();
};
$pm->childFirst();
$pm->run();
echo "DONE\n";
?>
--EXPECT--
DONE
