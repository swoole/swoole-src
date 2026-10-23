<?php

// Invoked by run_unwind_exit_php() in an isolated session, never directly by a PHPT worker.
[$directory, $target, $coroutines, $mode, $ipc] = array_slice($argv, 1);
$workerRole = str_starts_with($target, 'task') ? 'task' : 'event';
$workersFile = $directory . '/workers';
$errorsFile = $directory . '/errors';
$listener = stream_socket_server('tcp://127.0.0.1:0');
$address = stream_socket_get_name($listener, false);
$port = (int) substr($address, strrpos($address, ':') + 1);
fclose($listener);

function unwind_oom(): void
{
    $data = [];
    while (true) {
        $data[] = str_repeat('x', 1024 * 1024);
    }
}

function unwind_wait(callable $condition): mixed
{
    $deadline = microtime(true) + 5;
    do {
        if ($value = $condition()) {
            return $value;
        }
        usleep(10000);
    } while (microtime(true) < $deadline);
    throw new RuntimeException('Timed out waiting for worker termination or respawn');
}

function unwind_request(int $port, string $path): array
{
    $stream = @fsockopen('127.0.0.1', $port, $errno, $error, 0.1);
    if (!$stream) {
        return [0, ''];
    }
    stream_set_timeout($stream, 1);
    fwrite($stream, "GET $path HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    $reply = stream_get_contents($stream);
    fclose($stream);
    preg_match('/^HTTP\/1\.[01] (\d+)/', $reply, $status);
    return [(int) ($status[1] ?? 0), explode("\r\n\r\n", $reply, 2)[1] ?? ''];
}

$serverPid = pcntl_fork();
if ($serverPid === 0) {
    $role = 'master';
    $terminating = false;
    register_shutdown_function(function () use ($directory, &$role, &$terminating) {
        if ($terminating) {
            file_put_contents($directory . '/shutdown-' . getmypid(), json_encode([
                'role' => $role,
                'fatal' => (error_get_last()['type'] ?? 0) === E_ERROR,
            ]));
        }
    });
    $server = new Swoole\Http\Server('127.0.0.1', $port, (int) $mode);
    $server->set([
        'worker_num' => 1,
        'reactor_num' => 1,
        'enable_coroutine' => (bool) $coroutines,
        'task_worker_num' => $workerRole === 'task' ? 1 : 0,
        'task_enable_coroutine' => false,
        'task_ipc_mode' => (int) $ipc,
        'max_request' => $target === 'event-single' ? 0 : 100,
        'max_request_grace' => 0,
        'max_wait_time' => 1,
        'log_file' => $directory . '/server.log',
    ]);
    $server->on('ManagerStart', function () use ($directory, $target, &$role, &$terminating) {
        $role = 'manager';
        file_put_contents($directory . '/manager', (string) getmypid());
        if ($target === 'manager-start') {
            $terminating = true;
            unwind_oom();
        } elseif ($target === 'manager-timer') {
            Swoole\Timer::after(20, function () use (&$terminating) {
                $terminating = true;
                unwind_oom();
            });
        }
    });
    $server->on('WorkerStart', function ($server) use ($directory, $workersFile, $target, &$role, &$terminating) {
        $role = $server->taskworker ? 'task' : 'event';
        file_put_contents($workersFile, "$role:" . getmypid() . "\n", FILE_APPEND);
        if ($target === "$role-start" && !is_file($directory . '/startup-oom')) {
            file_put_contents($directory . '/startup-oom', 'ready');
            $terminating = true;
            unwind_oom();
        } elseif ($target === 'manager-error') {
            posix_kill(getmypid(), SIGKILL);
        }
    });
    $server->on('WorkerStop', function () use (&$terminating) {
        if ($terminating) {
            echo "unexpected worker stop callback\n";
        }
    });
    $server->on('ManagerStop', function () use (&$terminating) {
        if ($terminating) {
            echo "unexpected manager stop callback\n";
        }
    });
    $server->on('WorkerError', function ($server, $id, $pid, $code, $signal) use ($errorsFile, $target, &$terminating) {
        file_put_contents($errorsFile, json_encode([$pid, $code, $signal]) . "\n", FILE_APPEND);
        if ($target === 'manager-error') {
            $terminating = true;
            unwind_oom();
        }
    });
    if ($workerRole === 'task') {
        $server->on('Task', function () use (&$terminating) {
            $terminating = true;
            unwind_oom();
        });
        $server->on('Finish', function () {});
    }
    $server->on('Request', function ($request, $response) use ($server, $target, &$terminating) {
        if ($request->server['request_uri'] === '/boom') {
            if ($target === 'task') {
                $server->task('boom');
            } else {
                $terminating = true;
                unwind_oom();
            }
        }
        $response->end('ok:' . getmypid());
    });
    $server->start();
    if ($terminating) {
        echo "unexpected server continuation\n";
        exit(1);
    }
    exit(0);
}

try {
    if (str_starts_with($target, 'manager-')) {
        $managerPid = (int) unwind_wait(fn() => @file_get_contents($directory . '/manager'));
        $shutdown = unwind_wait(fn() => @file_get_contents($directory . '/shutdown-' . $managerPid));
        if (json_decode($shutdown, true) !== ['role' => 'manager', 'fatal' => true]) {
            throw new RuntimeException('Manager did not complete PHP request shutdown');
        }
    } else {
        unwind_wait(fn() => unwind_request($port, '/')[0] === 200);
        $oldPid = (int) unwind_wait(function () use ($workersFile, $workerRole) {
            preg_match('/^' . $workerRole . ':(\d+)$/m', @file_get_contents($workersFile) ?: '', $matches);
            return $matches[1] ?? false;
        });
        if (!str_ends_with($target, '-start')) {
            unwind_request($port, '/boom');
        }
        if ($target === 'event-single') {
            pcntl_waitpid($serverPid, $status);
            $serverPid = 0;
            if (!pcntl_wifexited($status) || pcntl_wexitstatus($status) !== 255) {
                throw new RuntimeException('Single-process server did not exit with status 255');
            }
        } else {
            $errors = unwind_wait(fn() => @file_get_contents($errorsFile));
            if (!in_array([$oldPid, 255, 0], array_map(fn($line) => json_decode($line, true), explode("\n", trim($errors))), true)) {
                throw new RuntimeException('Worker did not exit with status 255');
            }
        }
        $shutdown = unwind_wait(fn() => @file_get_contents($directory . '/shutdown-' . $oldPid));
        if (json_decode($shutdown, true) !== ['role' => $workerRole, 'fatal' => true]) {
            throw new RuntimeException('Worker did not complete PHP request shutdown');
        }
        if ($target !== 'event-single') {
            unwind_wait(function () use ($workersFile, $workerRole, $oldPid) {
                preg_match_all('/^' . $workerRole . ':(\d+)$/m', @file_get_contents($workersFile) ?: '', $matches);
                return array_filter($matches[1], fn($pid) => (int) $pid !== $oldPid);
            });
            for ($i = 0; $i < 3; $i++) {
                if (unwind_request($port, '/')[0] !== 200) {
                    throw new RuntimeException('A request after respawn did not return HTTP 200');
                }
            }
        }
    }
    echo "OK\n";
} finally {
    if ($serverPid > 0) {
        posix_kill($serverPid, SIGTERM);
        pcntl_waitpid($serverPid, $status);
    }
}
