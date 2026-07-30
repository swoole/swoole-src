--TEST--
swoole_server/task: return serialization exception
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Client;
use Swoole\Server;
use SwooleTest\ProcessManager;

$pm = new ProcessManager();

$pm->parentFunc = function () use ($pm) {
    $client = new Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    $client->set([
        'package_eof'    => "\r\n",
        'open_eof_check' => true,
        'open_eof_split' => true,
    ]);
    Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 10));

    $request = function (string $command) use ($client) {
        Assert::greaterThan($client->send($command . "\r\n"), 0);
        $response = $client->recv();
        Assert::string($response);

        return unserialize(trim($response));
    };

    $labels = [];

    $pid = $request('pid');
    Assert::integer($pid);
    $labels[] = 'PID';

    Assert::false($request('throw'));
    $labels[] = 'THROW';

    Assert::false($request('invalid'));
    $labels[] = 'INVALID';

    Assert::same($request('zero'), 0);
    $labels[] = 'ZERO';

    Assert::same($request('valid'), [$pid, 'OK']);
    $labels[] = 'VALID';

    echo implode("\n", $labels), "\n";

    $client->close();
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS, SWOOLE_SOCK_TCP);
    $server->set([
        'enable_coroutine' => false,
        'log_file'         => '/dev/null',
        'worker_num'       => 1,
        'task_worker_num'  => 1,
        'package_eof'      => "\r\n",
        'open_eof_check'   => true,
    ]);
    $server->on('workerStart', function (Server $server, int $workerId) use ($pm) {
        if ($workerId === 0) {
            $pm->wakeup();
        }
    });
    $server->on('receive', function (Server $server, int $fd, int $reactorId, string $data) {
        $command = trim($data);
        $result  = in_array($command, ['throw', 'invalid'], true)
            ? $server->taskwait($command)
            : $server->taskwait($command, 5);
        Assert::true($server->send($fd, serialize($result) . "\r\n"));
    });
    $server->on('task', function (Server $server, int $taskId, int $workerId, string $command) {
        return match ($command) {
            'pid'     => getmypid(),
            'throw'   => throw new RuntimeException('task callback failed'),
            'invalid' => $server,
            'zero'    => 0,
            'valid'   => [getmypid(), 'OK'],
        };
    });
    $server->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECTF--

Fatal error: Uncaught RuntimeException: task callback failed in %s:%d
Stack trace:
#0 [internal function]: {closure%S}(Object(Swoole\Server), %d, %d, 'throw')
#1 %s(%d): Swoole\Server->start()
#2 [internal function]: {closure%S}()
#3 %s(%d): call_user_func(Object(Closure))
#4 %s(%d): SwooleTest\ProcessManager->runChildFunc()
#5 [internal function]: SwooleTest\ProcessManager->%s(Object(Swoole\Process))
#6 %s(%d): Swoole\Process->start()
#7 %s(%d): SwooleTest\ProcessManager->run()
#8 {main}
  thrown in %s on line %d

Fatal error: Uncaught Exception: Serialization of 'Swoole\Server' is not allowed in %s:%d
Stack trace:
#0 %s(%d): Swoole\Server->start()
#1 [internal function]: {closure%S}()
#2 %s(%d): call_user_func(Object(Closure))
#3 %s(%d): SwooleTest\ProcessManager->runChildFunc()
#4 [internal function]: SwooleTest\ProcessManager->%s(Object(Swoole\Process))
#5 %s(%d): Swoole\Process->start()
#6 %s(%d): SwooleTest\ProcessManager->run()
#7 {main}
  thrown in %s on line %d
PID
THROW
INVALID
ZERO
VALID
