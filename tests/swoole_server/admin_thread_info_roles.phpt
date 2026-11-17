--TEST--
swoole_server: admin thread info executes only on owner reactor threads
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

ini_set('swoole.enable_library', '0');
$server = new Swoole\Server('127.0.0.1', get_constant_port(__FILE__), SWOOLE_PROCESS);
$server->set([
    'worker_num' => 1,
    'reactor_num' => 1,
    'task_worker_num' => 1,
    'admin_server' => 'unused',
    'log_file' => '/dev/null',
]);
$server->on('Receive', static function () {});
$server->on('Task', static function () {});
$server->on('Start', static function ($server) {
    foreach ([
        SWOOLE_SERVER_COMMAND_MASTER,
        SWOOLE_SERVER_COMMAND_MANAGER,
        SWOOLE_SERVER_COMMAND_EVENT_WORKER,
        SWOOLE_SERVER_COMMAND_TASK_WORKER,
    ] as $target) {
        Assert::false(@$server->command('get_thread_info', 0, $target, []));
    }
    $result = $server->command('get_thread_info', 0, SWOOLE_SERVER_COMMAND_REACTOR_THREAD, []);
    Assert::same($result['code'], 0);
    Assert::same($result['data']['id'], 0);
    Assert::integer($result['data']['dispatch_count']);
    Assert::integer($result['data']['event_num']);
    $commands = $server->command('get_all_commands', 0, SWOOLE_SERVER_COMMAND_MASTER, []);
    $threadCommands = array_values(array_filter($commands['data'], static fn ($command) => $command['name'] === 'get_thread_info'));
    Assert::count($threadCommands, 1);
    Assert::same($threadCommands[0]['accepted_process_types'], SWOOLE_SERVER_COMMAND_REACTOR_THREAD);
    $server->shutdown();
});
$server->start();
echo "DONE\n";
?>
--EXPECT--
DONE
