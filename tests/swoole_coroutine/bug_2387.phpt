--TEST--
swoole_coroutine: call_user_func_array
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_function_not_exist('curl_init');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require_once __DIR__ . '/../include/api/bug_2387/DbWrapper.php';
require_once __DIR__ . '/../include/api/bug_2387/MysqlPool.php';

use App\MysqlPool;

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    $data = curlGet("http://127.0.0.1:{$pm->getFreePort()}/list");
    assert(!empty($data) && count(json_decode($data, true)) > 0);
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $config = [
        'host' => MYSQL_SERVER_HOST,
        'port' => MYSQL_SERVER_PORT,
        'user' => MYSQL_SERVER_USER,
        'password' => MYSQL_SERVER_PWD,
        'database' => MYSQL_SERVER_DB,
        'timeout' => 0.5,
        'charset' => 'utf8mb4',
        'strict_type' => true,
        'pool_size' => '3',
        'pool_get_timeout' => 0.5,
    ];
    $httpServer = new Swoole\Http\Server('0.0.0.0', $pm->getFreePort(), SWOOLE_BASE);
    $httpServer->set([
        'log_file' => '/dev/null',
        'worker_num' => 1
    ]);
    $httpServer->on('WorkerStart', function (Swoole\Http\Server $server) use ($pm, $config) {
        try {
            MysqlPool::getInstance($config);
        } catch (\Exception $e) {
            echo $e->getMessage() . PHP_EOL;
            $server->shutdown();
        } catch (\Throwable $throwable) {
            echo $throwable->getMessage() . PHP_EOL;
            $server->shutdown();
        }
        $pm->wakeup();
    });
    $httpServer->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        if ($request->server['path_info'] == '/list') {
            go(function () use ($request, $response) {
                try {
                    $pool = MysqlPool::getInstance();
                    $mysql = $pool->get();
                    defer(function () use ($mysql) {
                        MysqlPool::getInstance()->put($mysql);
                        echo "size = " . MysqlPool::getInstance()->getLength() . PHP_EOL;
                    });
                    $result = $mysql->query("show tables");
                    $response->end(json_encode($result));
                } catch (\Exception $e) {
                    $response->end($e->getMessage());
                }
            });
        }
    });
    $httpServer->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
size = 3
