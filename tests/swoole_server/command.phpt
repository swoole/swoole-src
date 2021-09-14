--TEST--
swoole_server: command [1]
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;

$server = new Server('127.0.0.1', get_one_free_port(), SWOOLE_PROCESS);
$server->addCommand('test_getpid', SWOOLE_SERVER_COMMAND_MASTER | SWOOLE_SERVER_COMMAND_EVENT_WORKER,
    function ($server) {
        return json_encode(['pid' => posix_getpid()]);
    });
$server->set([
    'log_file' => '/dev/null',
    'worker_num' => 2,
]);

$server->on('start', function (Server $serv) {
    $result = $serv->command('test_getpid', 0, SWOOLE_SERVER_COMMAND_MASTER, ['type' => 'master']);
    Assert::eq($result['pid'], $serv->getMasterPid());
    $result = $serv->command('test_getpid', 1, SWOOLE_SERVER_COMMAND_EVENT_WORKER, ['type' => 'worker']);
    Assert::eq($result['pid'], $serv->getWorkerPid(1));
    $result = $serv->command('test_not_found', 1, SWOOLE_SERVER_COMMAND_EVENT_WORKER, ['type' => 'worker']);
    Assert::false($result);

    $serv->shutdown();
});

$server->on('request', function (Request $request, Response $response) {
});
$server->start();
echo "DONE\n";
?>
--EXPECT--
DONE
