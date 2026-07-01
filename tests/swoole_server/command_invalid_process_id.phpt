--TEST--
swoole_server: command invalid process id
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;

$server = new Server('127.0.0.1', get_one_free_port(), SWOOLE_PROCESS);
$server->addCommand('test_getpid', SWOOLE_SERVER_COMMAND_EVENT_WORKER, function ($server) {
    return json_encode(['pid' => posix_getpid()]);
});
$server->set([
    'log_file' => '/dev/null',
    'worker_num' => 2,
]);

$server->on('start', function (Server $serv) {
    $errors = [];
    set_error_handler(function (int $errno, string $errstr) use (&$errors) {
        $errors[] = $errstr;
        return true;
    });

    Assert::false($serv->command('test_getpid', 65536, SWOOLE_SERVER_COMMAND_EVENT_WORKER, []));
    Assert::false($serv->command('test_getpid', PHP_INT_MAX, SWOOLE_SERVER_COMMAND_EVENT_WORKER, []));
    Assert::eq(count($errors), 1);
    Assert::contains($errors[0], 'invalid process_id');

    restore_error_handler();
    $serv->shutdown();
});

$server->on('request', function (Request $request, Response $response) {
});
$server->start();
echo "DONE\n";
?>
--EXPECT--
DONE
