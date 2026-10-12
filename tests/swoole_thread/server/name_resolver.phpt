--TEST--
NameResolver: THREAD server registers once in the master and deregisters on shutdown
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_nts();
if (!defined('SWOOLE_THREAD')) die('skip thread server required');
?>
--FILE--
<?php
use Swoole\Coroutine;
use Swoole\Thread;

class ServerResolver extends Swoole\NameResolver {
    public function __construct(private string $journal) {}
    private function record(string $event): void {
        file_put_contents($this->journal, json_encode(['event' => $event, 'thread' => Thread::getId()]) . "\n", FILE_APPEND | LOCK_EX);
    }
    public function join(string $name, string $ip, int $port, array $options = []): bool { $this->record('join'); return true; }
    public function leave(string $name, string $ip, int $port): bool { $this->record('leave'); return true; }
    public function heartbeat(string $name, string $ip, int $port, array $options = []): bool { $this->record('beat'); return true; }
    public function getCluster(string $name): ?Swoole\NameResolver\Cluster { return null; }
}
$args = Thread::getArguments();
$journal = $args[0] ?? tempnam(sys_get_temp_dir(), 'swoole-thread-discovery-');
$server = new Swoole\Http\Server('127.0.0.1', 0, SWOOLE_THREAD);
$server->set(['worker_num' => 2, 'reactor_num' => 1, 'log_file' => '/dev/null', 'max_wait_time' => 1,
    'service_name' => 'thread.service', 'service_resolver' => new ServerResolver($journal),
    'service_heartbeat_interval' => 0.02, 'init_arguments' => fn() => [$journal]]);
$server->on('request', fn($request, $response) => $response->end('OK'));
$server->on('workerStart', function ($server, $workerId) use ($journal) {
    if ($workerId !== 0) return;
    Coroutine::create(function () use ($server, $journal) {
        try {
            $deadline = microtime(true) + 3;
            do {
                $events = file($journal, FILE_IGNORE_NEW_LINES);
                if (count($events) >= 4) return;
                Coroutine::sleep(0.01);
            } while (microtime(true) < $deadline);
            throw new RuntimeException('Heartbeat did not start');
        } finally {
            $server->shutdown();
        }
    });
});
$server->start();
if (!$args) {
    try {
        $events = array_map(fn($line) => json_decode($line, true, 512, JSON_THROW_ON_ERROR), file($journal, FILE_IGNORE_NEW_LINES));
        $counts = array_count_values(array_column($events, 'event'));
        if (($counts['join'] ?? 0) !== 1 || ($counts['leave'] ?? 0) !== 1 || ($counts['beat'] ?? 0) < 3
            || array_unique(array_column($events, 'thread')) !== [Thread::getId()] || end($events)['event'] !== 'leave') {
            throw new RuntimeException(json_encode($events));
        }
    } finally {
        unlink($journal);
    }
    echo "DONE\n";
}
?>
--EXPECT--
DONE
