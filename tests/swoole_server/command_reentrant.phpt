--TEST--
swoole_server: nested master commands and consecutive worker responses
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$server = new Swoole\Http\Server('127.0.0.1', get_one_free_port(), SWOOLE_PROCESS);
$server->set(['worker_num' => 2, 'log_file' => '/dev/null']);
$server->addCommand('echo', SWOOLE_SERVER_COMMAND_MASTER | SWOOLE_SERVER_COMMAND_EVENT_WORKER,
    function ($server, $message) {
        $request = json_decode($message, true);
        if (!empty($request['nested'])) {
            return json_encode($server->command('echo', 0, SWOOLE_SERVER_COMMAND_MASTER, ['id' => $request['id']]));
        }
        return json_encode($request);
    });
$server->on('Start', function ($server) {
    for ($id = 0; $id < 32; $id++) {
        Assert::same($server->command('echo', 0, SWOOLE_SERVER_COMMAND_MASTER, ['id' => $id, 'nested' => true]),
            ['id' => $id]);
        Assert::same($server->command('echo', 1, SWOOLE_SERVER_COMMAND_EVENT_WORKER, ['id' => $id]),
            ['id' => $id]);
    }
    $server->shutdown();
});
$server->on('Request', function ($request, $response) {});
$server->start();
echo "DONE\n";
?>
--EXPECT--
DONE
