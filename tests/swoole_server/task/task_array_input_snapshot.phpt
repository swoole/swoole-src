--TEST--
swoole_server/task: keep task input snapshots and returned values alive across serialization
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php

require __DIR__ . '/../../include/bootstrap.php';

class TaskArrayMutation
{
    public function __construct(public string $value)
    {
    }

    public function __serialize(): array
    {
        $GLOBALS['batch'] = ['replacement'];
        return ['value' => $this->value];
    }

    public function __unserialize(array $data): void
    {
        $this->value = $data['value'];
    }
}
function check_snapshot($server, string $method): void
{
    $GLOBALS['batch'] = ['first' => new TaskArrayMutation('first'), 4 => 'second'];
    $results          = $server->{$method}($GLOBALS['batch'], 5);
    Assert::same($GLOBALS['batch'], ['replacement']);
    gc_collect_cycles();
    $expected = [];
    foreach (['first', 'second'] as $value) {
        $expected[] = ['payload' => $value, 'nested' => ['value' => $value], 'buffer' => str_repeat($value, 100)];
    }
    Assert::count($results, 2);
    Assert::same($results[0], $expected[0]);
    Assert::same($results[1], $expected[1]);
}
foreach ([false, true] as $enableCoroutine) {
    $pm             = new ProcessManager();
    $pm->parentFunc = function () use ($pm) {
        $client = new Swoole\Client(SWOOLE_SOCK_TCP);
        Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 5));
        $client->send('run');
        Assert::same($client->recv(), 'OK');
        $client->close();
        $pm->kill();
    };
    $pm->childFunc = function () use ($pm, $enableCoroutine) {
        $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
        $server->set(['worker_num' => 1, 'task_worker_num' => 2, 'enable_coroutine' => $enableCoroutine, 'log_file' => '/dev/null']);
        $server->on('WorkerStart', function ($server, $id) use ($pm) {
            if ($id === 0) {
                $pm->wakeup();
            }
        });
        $server->on('Receive', function ($server, $fd) use ($enableCoroutine) {
            check_snapshot($server, 'taskWaitMulti');
            if ($enableCoroutine) {
                check_snapshot($server, 'taskCo');
            }
            $server->send($fd, 'OK');
        });
        $server->on('Task', function ($server, $id, $source, $data) {
            $value = is_object($data) ? $data->value : $data;
            return ['payload' => $value, 'nested' => ['value' => $value], 'buffer' => str_repeat($value, 100)];
        });
        $server->on('Finish', function () {});
        $server->start();
    };
    $pm->childFirst();
    $pm->run();
}
echo "DONE\n";
?>
--EXPECT--
DONE
