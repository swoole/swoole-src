--TEST--
swoole_server: bind event and task workers to available CPUs in BASE and PROCESS modes
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_process_affinity();
skip('requires two CPUs', count(Swoole\Process::getAffinity()) < 2);
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Process;
use Swoole\Server;
use Swoole\Table;
use Swoole\Timer;

$original = Process::getAffinity();
$cpus = [$original[0], $original[count($original) - 1]];

foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    foreach (['default', 'ignore', 'disabled'] as $case) {
        $pid = pcntl_fork();
        Assert::greaterThanEq($pid, 0);
        if ($pid === 0) {
            Assert::true(Process::setAffinity($cpus));
            $results = new Table(16);
            $results->column('cpus', Table::TYPE_STRING, 128);
            $results->create();
            $server = new Server('127.0.0.1', 0, $mode);
            $server->set([
                'worker_num' => 2,
                'reactor_num' => 1,
                'task_worker_num' => 2,
                'open_cpu_affinity' => $case !== 'disabled',
                'log_file' => '/dev/null',
            ]);
            if ($case !== 'default') {
                // Repeated set() replaces the old ignore list. Invalid and duplicate IDs are harmless.
                $server->set(['cpu_affinity_ignore' => [$cpus[1]]]);
                $server->set(['cpu_affinity_ignore' => [-1, PHP_INT_MAX, $cpus[0], $cpus[0]]]);
            }
            $server->on('workerStart', function (Server $server, int $workerId) use ($results) {
                $results->set((string) $workerId, ['cpus' => json_encode(Process::getAffinity())]);
                if ($workerId === 0) {
                    Timer::tick(10, function (int $timerId) use ($server, $results) {
                        if (count($results) === 4) {
                            Timer::clear($timerId);
                            $server->shutdown();
                        }
                    });
                    Timer::after(5000, function () use ($server) {
                        $server->shutdown();
                    });
                }
            });
            $server->on('receive', function () {});
            $server->on('task', function () {});
            $server->on('finish', function () {});
            Assert::true($server->start());
            Assert::same(count($results), 4);
            for ($workerId = 0; $workerId < 4; $workerId++) {
                $expected = $case === 'disabled' ? $cpus : [$cpus[$case === 'ignore' ? 1 : $workerId % 2]];
                Assert::same(json_decode($results->get((string) $workerId, 'cpus'), true), $expected);
            }
            Assert::same(Process::getAffinity(), $cpus);
            exit;
        }
        Assert::same(pcntl_waitpid($pid, $status), $pid);
        Assert::true(pcntl_wifexited($status));
        Assert::same(pcntl_wexitstatus($status), 0);
    }
}
Assert::same(Process::getAffinity(), $original);
echo "DONE\n";
?>
--EXPECT--
DONE
