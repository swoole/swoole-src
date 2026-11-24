<?php
// Offload a job to a task worker with task() and get the result in finish().
// Run: php examples/task/basic.php (press Ctrl+C to stop)
$server = new Swoole\Server('127.0.0.1', 9504);
$server->set(['worker_num' => 1, 'task_worker_num' => 1]);
$server->on('receive', function ($server, $fd, $reactorId, $data) {
    $server->task(trim($data));
});
$server->on('task', function ($server, $taskId, $srcWorkerId, $data) {
    echo "task worker got: $data" . PHP_EOL;
    return strtoupper($data);
});
$server->on('finish', function ($server, $taskId, $result) {
    echo "task finished: $result" . PHP_EOL;
});
$server->start();
