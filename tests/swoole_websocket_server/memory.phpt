--TEST--
swoole_websocket_server: memory trace
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_top();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

define('FRAME_DATA_SIZE', 100 * 1024);
define('REQUESTS_TIMES', 24);

$pm = new ProcessManager();
$pm->parentFunc = function () use ($pm) {
    phpt_echo("start to benchmark " . REQUESTS_TIMES . " times...\n");
    $concurrency = PRESSURE_LEVEL === PRESSURE_NORMAL ? MAX_CONCURRENCY * 16 : MAX_CONCURRENCY;
    co::set(['max_coroutine' => $concurrency]);
    for ($c = $concurrency; $c--;) {
        go(function () use ($pm, $c) {
            $cli = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
            $cli->set(['timeout' => -1]);
            $ret = 0;
            while (!$cli->upgrade('/')) {
                ++$ret > 3 && exit("ERROR\n");
            }
            while ($cli->recv(-1)) {
                continue;
            }
        });
    }
    swoole_event_wait();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Websocket\Server('127.0.0.1', $pm->getFreePort());
    $server->set(['worker_num' => 1, 'log_file' => '/dev/null']);
    $server->on('workerStart', function (Swoole\Websocket\Server $server, int $worker_id) use ($pm) {
        global $mem_records;
        co::sleep(SERVER_PREHEATING_TIME);
        $pm->wakeup();
        while (true) {
            $master_top = top($server->master_pid);
            $worker_top = top($server->worker_pid);
            $mem_records[] = [
                'master_virtual' => $master_top['VIRT'],
                'master_real' => $master_top['RES'],
                'worker_virtual' => $worker_top['VIRT'],
                'worker_real' => $worker_top['RES']
            ];
            phpt_var_dump(end($mem_records));
            if (($records_count = count($mem_records)) === REQUESTS_TIMES) {
                phpt_echo("=== master virtual ===\n");
                phpt_var_dump($master_virtual = array_column($mem_records, 'master_virtual'));
                phpt_echo("=== master real ===\n");
                phpt_var_dump($master_real = array_column($mem_records, 'master_real'));
                phpt_echo("=== worker virtual ===\n");
                phpt_var_dump($worker_virtual = array_column($mem_records, 'worker_virtual'));
                phpt_echo("=== worker real ===\n");
                phpt_var_dump($worker_real = array_column($mem_records, 'worker_real'));
                for ($i = $records_count / 2; $i < $records_count; $i++) {
                    assert(approximate($master_virtual[$i], $master_virtual[$records_count / 2]));
                    assert(approximate($worker_virtual[$i], $worker_virtual[$records_count / 2]));
                    assert(approximate($worker_real[$i], $worker_real[$records_count / 2]));
                }
                $server->shutdown();
                return;
            }
            $connections = iterator_to_array($server->connections);
            $fd = 0;
            $success = 0;
            foreach ($connections as $fd) {
                if (@$server->push($fd, str_repeat('S', FRAME_DATA_SIZE))) {
                    $success++;
                }
            }
            phpt_echo("#{$records_count}: push " . (FRAME_DATA_SIZE / 1024) . "k data to {$fd} client success {$success}!\n");
            co::sleep(REQUESTS_WAIT_TIME);
            usleep(1);
        }
    });
    $server->on('message', function (Swoole\Websocket\Server $server, Swoole\WebSocket\Frame $frame) { });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
