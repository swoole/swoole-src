--TEST--
swoole_server: invalid admin command parameters do not terminate command owners
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

// Register the native commands without starting the separate library admin HTTP listener.
ini_set('swoole.enable_library', '0');
$server = new Swoole\Server('127.0.0.1', get_constant_port(__FILE__), SWOOLE_PROCESS);
$server->set([
    'worker_num' => 1,
    'task_worker_num' => 1,
    'admin_server' => 'unused',
    'log_file' => '/dev/null',
]);
$server->on('Task', static function () {});
$server->on('Receive', static function () {});
$server->on('Start', static function ($server) {
    // PROCESS commands originate on the master and execute on their selected owner.
    $invalid = [null, false, 123, [], ['nested' => 'value']];
    foreach ([
        SWOOLE_SERVER_COMMAND_MASTER,
        SWOOLE_SERVER_COMMAND_MANAGER,
        SWOOLE_SERVER_COMMAND_EVENT_WORKER,
        SWOOLE_SERVER_COMMAND_TASK_WORKER,
    ] as $target) {
        foreach (['get_all_unix_sockets' => 'type', 'get_socket_info' => 'fd'] as $command => $field) {
            foreach ($invalid as $value) {
                $result = $server->command($command, 0, $target, [$field => $value]);
                Assert::isArray($result);
                Assert::same($result['code'], 4003);
            }
        }
        $result = $server->command('get_all_unix_sockets', 0, $target, ['type' => 'event']);
        Assert::same($result['code'], 0);
    }
    foreach ($invalid as $value) {
        $result = $server->command(
            'get_connection_info', 0, SWOOLE_SERVER_COMMAND_REACTOR_THREAD, ['session_id' => $value]
        );
        Assert::same($result['code'], 4003);
    }
    $result = $server->command(
        'get_connection_info', 0, SWOOLE_SERVER_COMMAND_REACTOR_THREAD, ['session_id' => '0']
    );
    Assert::same($result['code'], 4004);
    $server->shutdown();
});
$server->start();
echo "DONE\n";
?>
--EXPECT--
DONE
