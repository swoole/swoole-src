--TEST--
swoole_server: BASE cross-worker SendFile transfer and cleanup
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Client;
use Swoole\SendFile;
use Swoole\Server;

use function Swoole\Coroutine\run;

foreach ([false, true] as $object) {
    $path    = tempnam(sys_get_temp_dir(), 'swoole-sendfile-forward-');
    $content = str_repeat('cross-worker sendfile payload', 16384);
    file_put_contents($path, $content);
    $ready          = new Swoole\Atomic();
    $pm             = new ProcessManager();
    $pm->parentFunc = function () use ($pm, $path, $content) {
        run(function () use ($pm, $path, $content) {
            $client = new Client(SWOOLE_SOCK_TCP);
            $client->set(['timeout' => 5]);
            Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 5));
            Assert::greaterThan($client->send("transfer\n"), 0);
            $received = '';
            while (strlen($received) < strlen($content)) {
                $chunk = $client->recv();
                if ($chunk === '' || $chunk === false) {
                    break;
                }
                $received .= $chunk;
            }
            Assert::same($received, $content);
            $client->close();
        });
        $deadline = microtime(true) + 5;
        do {
            clearstatcache(true, $path);
            if (!is_file($path)) {
                break;
            }
            usleep(1000);
        } while (microtime(true) < $deadline);
        Assert::false(is_file($path));
        $pm->kill();
    };
    $pm->childFunc = function () use ($pm, $path, $ready, $object) {
        $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
        $server->set([
            'worker_num'     => 2,
            'log_file'       => '/dev/null',
            'open_eof_check' => true,
            'package_eof'    => "\n",
        ]);
        $server->on('workerStart', function () use ($ready, $pm) {
            if ($ready->add() === 2) {
                $pm->wakeup();
            }
        });
        $server->on('receive', function (Server $server, int $fd) {
            // The receiving worker owns this socket; the other worker must forward the file back.
            Assert::true($server->sendMessage($fd, 1 - $server->worker_id));
        });
        $server->on('pipeMessage', function (Server $server, int $source, int $fd) use ($path, $object) {
            Assert::notSame($server->worker_id, $source);
            if ($object) {
                $file = new SendFile($path);
                $file->deleteAfterSend = true;
                Assert::true($server->sendfile($fd, $file));
            } else {
                Assert::true($server->sendfile($fd, $path, delete_file: true));
            }
        });
        $server->start();
    };
    $pm->childFirst();
    $pm->run();
}
echo "DONE\n";
?>
--EXPECT--
DONE
