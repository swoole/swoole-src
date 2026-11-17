--TEST--
swoole_server: admin commands validate the complete numeric ID and its target range
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
$server->on('Task', static function () {});
$server->on('Receive', static function () {});
$server->on('Start', static function ($server) {
    $invalid = [
        '', ' ', '-1', '+1', '1suffix', '1.0', '0x10', "1\0suffix",
        (string) PHP_INT_MAX . '0', str_repeat('9', 100),
    ];
    foreach ([
        SWOOLE_SERVER_COMMAND_MASTER,
        SWOOLE_SERVER_COMMAND_MANAGER,
        SWOOLE_SERVER_COMMAND_EVENT_WORKER,
        SWOOLE_SERVER_COMMAND_TASK_WORKER,
    ] as $target) {
        foreach (array_merge($invalid, ['2147483648', '4294967296']) as $id) {
            $result = $server->command('get_socket_info', 0, $target, ['fd' => $id]);
            Assert::same($result['code'], 4003, json_encode($id));
        }
        // INT_MAX is a syntactically valid fd, even though it does not identify an open socket.
        $result = $server->command('get_socket_info', 0, $target, ['fd' => '2147483647']);
        Assert::notSame($result['code'], 4003);
    }
    foreach ($invalid as $id) {
        $result = $server->command('get_connection_info', 0, SWOOLE_SERVER_COMMAND_REACTOR_THREAD, ['session_id' => $id]);
        Assert::same($result['code'], 4003, json_encode($id));
    }
    // Session IDs use their full native width. These valid IDs are absent, rather than malformed.
    foreach (['0', '000', (string) PHP_INT_MAX] as $id) {
        $result = $server->command('get_connection_info', 0, SWOOLE_SERVER_COMMAND_REACTOR_THREAD, ['session_id' => $id]);
        Assert::same($result['code'], 4004);
    }
    $server->shutdown();
});
$server->start();
echo "DONE\n";
?>
--EXPECT--
DONE
