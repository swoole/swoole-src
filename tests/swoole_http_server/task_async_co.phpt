--TEST--
swoole_http_server: use async io and coroutine in task process
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
// Swoole\Runtime::enableCoroutine();
$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    for ($n = MAX_REQUESTS; $n--;) {
        if (!assert(($res = curlGet("http://127.0.0.1:{$pm->getFreePort()}/task?n={$n}")) === 'OK')) {
            echo "{$res}\n";
            break;
        }
    }
    echo "DONE\n";
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $server = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set([
        'log_file' => '/dev/null',
        'task_worker_num' => 1
    ]);
    $server->on('workerStart', function ($serv, $wid) use ($pm) {
        $pm->wakeup();
    });
    $server->on('request', function (swoole_http_request $request, swoole_http_response $response) use ($server) {
        static $randoms;
        if (!$randoms) {
            for ($n = MAX_REQUESTS; $n--;) {
                $randoms[] = openssl_random_pseudo_bytes(mt_rand(0, 65536));
            }
            $pdo = new PDO(
                "mysql:host=" . MYSQL_SERVER_HOST . ";dbname=" . MYSQL_SERVER_DB . ";charset=utf8",
                MYSQL_SERVER_USER, MYSQL_SERVER_PWD
            );
            $sql = <<<SQL
DROP TABLE IF EXISTS `incr`;
CREATE TABLE `incr` (`id` int(10) unsigned NOT NULL AUTO_INCREMENT, PRIMARY KEY (`id`));
INSERT INTO `incr` VALUES (1);
SQL;
            $pdo->exec($sql);
        }
        $n = $request->get['n'];
        switch ($request->server['path_info']) {
            case '/task':
                {
                    list($ret_n, $ret_random) = $server->taskCo([$n], 1)[0];
                    if ($ret_n !== $n) {
                        $response->end("ERROR MATCH {$ret_n} with {$n}");
                        return;
                    } elseif ($ret_random !== $randoms[$n]) {
                        $response->end("ERROR EQUAL {$ret_n}(" . strlen($ret_random) . ") with {$n}(" . strlen($randoms[$n]) . ")");
                        return;
                    }
                    $response->end('OK');
                    break;
                }
            case '/random':
                {
                    $response->end($randoms[$n]);
                    break;
                }
        }
    });
    $server->on('task', function (swoole_http_server $server, int $task_id, int $worker_id, string $n) use ($pm) {
        go(function () use ($pm, $server, $n) {
            $cli = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
            $cli->get("/random?n={$n}");
            $server->finish([$n, $cli->body]);
        });
        go(function () use ($n) {
            global $pdo;
            $pdo = $pdo ?? new PDO(
                    "mysql:host=" . MYSQL_SERVER_HOST . ";dbname=" . MYSQL_SERVER_DB . ";charset=utf8",
                    MYSQL_SERVER_USER, MYSQL_SERVER_PWD
                );
            $pdo->exec('UPDATE `incr` SET `id` = `id` + 1');
            if ($n == 0) {
                echo $pdo->query('SELECT `id` FROM `incr`')->fetch(PDO::FETCH_ASSOC)['id'] . "\n";
                @$pdo->exec('DROP TABLE IF EXISTS `incr`');
            }
        });
    });
    $server->on('finish', function () { });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
100
DONE
