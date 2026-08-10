<?php

namespace SwooleTest;

use RuntimeException;
use Swoole\Process;
use Swoole;
use Throwable;
use function Swoole\Coroutine\run as run;

class CurlManager
{
    protected $port;
    protected $nativeCurl = false;
    protected $serverLogFile;

    function __construct() {
        $this->nativeCurl = defined('SWOOLE_HOOK_NATIVE_CURL');
    }

    function disableNativeCurl() {
        $this->nativeCurl = false;
    }

    function getUrlBase()
    {
        return "http://127.0.0.1:{$this->port}";
    }

    protected function runCliServer()
    {
        $this->serverLogFile = tempnam(sys_get_temp_dir(), 'swoole-curl-');
        if ($this->serverLogFile === false) {
            throw new RuntimeException('Unable to create the PHP CLI server log');
        }

        $exec = sprintf(
            'exec %s -n -S 127.0.0.1:0 -t %s %s >> %s 2>&1',
            escapeshellarg(PHP_BINARY),
            escapeshellarg(__DIR__),
            escapeshellarg(__DIR__ . '/responder/get.php'),
            escapeshellarg($this->serverLogFile)
        );
        $proc = new Process(function (Process $p) use ($exec) {
            $p->exec('/bin/sh', ['-c', $exec]);
        });

        if (!$proc->start()) {
            @unlink($this->serverLogFile);
            throw new RuntimeException('Unable to start the PHP CLI server process');
        }

        $deadline = microtime(true) + 5;
        do {
            $log = @file_get_contents($this->serverLogFile);
            if ($log !== false && preg_match('#Development Server \(http://127\.0\.0\.1:(\d+)\)#', $log, $matches)) {
                $this->port = (int) $matches[1];
                return $proc;
            }
            // Process::wait() is process-global and may discard another direct child's status while reaping ours.
            $waitInfo = Process::wait(false);
            if ($waitInfo && $waitInfo['pid'] === $proc->pid) {
                $this->throwCliServerStartupException($log ?: '');
            }
            usleep(10000);
        } while (microtime(true) < $deadline);

        $this->terminateCliServer($proc);
        $log = @file_get_contents($this->serverLogFile);
        $this->throwCliServerStartupException($log ?: '');
    }

    private function terminateCliServer(Process $proc)
    {
        @Process::kill($proc->pid);
        $deadline = microtime(true) + 1;
        do {
            $waitInfo = Process::wait(false);
            if ($waitInfo && $waitInfo['pid'] === $proc->pid) {
                return;
            }
            usleep(10000);
        } while (microtime(true) < $deadline);

        @Process::kill($proc->pid, SIGKILL);
        do {
            $waitInfo = Process::wait(true);
        } while ($waitInfo && $waitInfo['pid'] !== $proc->pid);
    }

    private function throwCliServerStartupException(string $log): void
    {
        @unlink($this->serverLogFile);
        $log = trim(substr($log, -2048));
        if ($log !== '') {
            $log = ":\n{$log}";
        }
        throw new RuntimeException("PHP CLI server did not become ready{$log}");
    }

    function run(callable $fn, $createCliServer = true)
    {
        if ($createCliServer) {
            $proc = $this->runCliServer();
        } else {
            $proc = null;
        }

        $throwable = null;
        try {
            global $argc, $argv;
            if (!($argc > 1 and $argv[1] == 'ori')) {
                $flags = $this->nativeCurl ? SWOOLE_HOOK_NATIVE_CURL : SWOOLE_HOOK_CURL;
                Swoole\Runtime::enableCoroutine($flags);
            }

            run(function () use ($fn, &$throwable) {
                try {
                    $fn("127.0.0.1:{$this->port}");
                } catch (Throwable $e) {
                    $throwable = $e;
                }
            });
        } finally {
            if ($proc) {
                $this->terminateCliServer($proc);
                @unlink($this->serverLogFile);
            }
        }

        if ($throwable) {
            throw $throwable;
        }
    }
}
