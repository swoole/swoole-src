<?php
function verify($value): void { if (!$value) throw new RuntimeException('Assertion failed'); }
$journal = tempnam(sys_get_temp_dir(), 'swoole-discovery-');
function records(): array {
    global $journal;
    return array_map(fn($line) => json_decode($line, true, 512, JSON_THROW_ON_ERROR), file($journal, FILE_IGNORE_NEW_LINES));
}
function awaitRecords(callable $ready): array {
    $deadline = microtime(true) + 8;
    do {
        $events = records();
        if ($ready($events)) return $events;
        Swoole\Coroutine::sleep(0.01);
    } while (microtime(true) < $deadline);
    throw new RuntimeException('Timed out: ' . json_encode($events));
}
$process = new Swoole\Process(function () use ($journal) {
    $resolver = new class($journal) extends Swoole\NameResolver {
        public function __construct(private string $journal) {}
        private function record(string $event): void {
            file_put_contents($this->journal, json_encode(['event' => $event, 'pid' => getmypid()]) . "\n", FILE_APPEND | LOCK_EX);
        }
        public function join(string $name, string $ip, int $port, array $options = []): bool { $this->record('join'); return true; }
        public function leave(string $name, string $ip, int $port): bool { $this->record('leave'); return true; }
        public function heartbeat(string $name, string $ip, int $port, array $options = []): bool { $this->record('beat'); return true; }
        public function getCluster(string $name): ?Swoole\NameResolver\Cluster { return null; }
    };
    $server = new Swoole\Http\Server('127.0.0.1', 0, SERVER_MODE);
    $server->set(['worker_num' => SERVER_MODE === SWOOLE_BASE ? 2 : 1, 'reactor_num' => 1, 'log_file' => '/dev/null', 'max_wait_time' => 1,
        'service_name' => 'reload.service', 'name_resolver' => [$resolver], 'service_heartbeat_interval' => 0.02]);
    $server->on('workerStart', function ($server, $workerId) use ($journal) {
        if ($workerId !== 0) return;
        file_put_contents($journal, json_encode(['event' => 'worker', 'pid' => getmypid()]) . "\n", FILE_APPEND | LOCK_EX);
    });
    $server->on('request', fn($request, $response) => $response->end('OK'));
    $server->start();
}, false, 0, false);
$pid = $process->start();
verify($pid > 0);
$reaped = false;
try {
    Swoole\Coroutine\run(function () use ($pid, &$reaped) {
        $events = awaitRecords(fn($events) => count(array_filter($events, fn($e) => $e['event'] === 'beat')) >= 3
            && count(array_filter($events, fn($e) => $e['event'] === 'worker')) >= 1);
        $worker = array_values(array_filter($events, fn($e) => $e['event'] === 'worker'))[0]['pid'];
        verify(Swoole\Process::kill($worker, SIGKILL));
        $afterCrash = SERVER_MODE === SWOOLE_BASE ? 2 : 1;
        awaitRecords(fn($events) => count(array_filter($events, fn($e) => $e['event'] === 'worker')) >= 2
            && count(array_filter($events, fn($e) => $e['event'] === 'join')) >= $afterCrash);
        verify(Swoole\Process::kill($pid, SIGUSR1));
        $expectedJoins = SERVER_MODE === SWOOLE_BASE ? 3 : 1;
        $events = awaitRecords(fn($events) => count(array_filter($events, fn($e) => $e['event'] === 'worker')) >= 3
            && count(array_filter($events, fn($e) => $e['event'] === 'join')) >= $expectedJoins);
        verify(count(array_filter($events, fn($e) => $e['event'] === 'join')) === $expectedJoins);
        verify(count(array_filter($events, fn($e) => $e['event'] === 'leave')) === 0);
        verify(Swoole\Process::kill($pid, SIGTERM));
        awaitRecords(fn($events) => count(array_filter($events, fn($e) => $e['event'] === 'leave')) === 1);
        $deadline = microtime(true) + 5;
        do {
            $status = Swoole\Process::wait(false);
            if ($status) { verify($status['pid'] === $pid && $status['code'] === 0); $reaped = true; break; }
            Swoole\Coroutine::sleep(0.01);
        } while (microtime(true) < $deadline);
        verify($reaped);
        $operations = array_values(array_filter(records(), fn($e) => in_array($e['event'], ['join', 'beat', 'leave'], true)));
        $owners = array_filter($operations, fn($e) => $e['event'] !== 'leave');
        verify(count(array_unique(array_column($owners, 'pid'))) === $expectedJoins);
        verify(end($operations)['event'] === 'leave');
    });
} finally {
    if (!$reaped) { Swoole\Process::kill($pid, SIGTERM); Swoole\Process::wait(); }
    unlink($journal);
}
echo "DONE\n";
?>
