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

    protected function runCliServer($port)
    {
        $proc = new Process(function (Process $p) use ($port) {
            $exec = "exec /usr/bin/env php -t " . __DIR__ . " -n -S 127.0.0.1:{$port} " . __DIR__ . "/responder/get.php";
            $p->exec('/bin/sh', ['-c', $exec]);
        }, true, 1);

        if (!$proc->start()) {
            throw new RuntimeException('Unable to start the PHP CLI server process');
        }

        $i = 0;
        while ($i++ < 500) {
            usleep(10000);
            if (@file_get_contents($this->getUrlBase() . '/')) {
                return $proc;
            }
        }

        $this->stopCliServer($proc);
        throw new RuntimeException('PHP CLI server did not become ready');
    }

    protected function stopCliServer(Process $proc)
    {
        @Process::kill($proc->pid);
        if (!function_exists('pcntl_waitpid')) {
            Process::wait();
        } else {
            pcntl_waitpid($proc->pid, $status);
        }
    }

    function run(callable $fn, $createCliServer = true)
    {
        if ($createCliServer) {
            $this->port = get_one_free_port();
            $proc = $this->runCliServer($this->port);
        } else {
            $proc = null;
        }

        global $argc, $argv;
        if (!($argc > 1 and $argv[1] == 'ori')) {
            $flags = $this->nativeCurl ? SWOOLE_HOOK_NATIVE_CURL : SWOOLE_HOOK_CURL;
            Swoole\Runtime::enableCoroutine($flags);
        }

        $throwable = null;
        try {
            run(function () use ($fn, &$throwable) {
                try {
                    $fn("127.0.0.1:{$this->port}");
                } catch (Throwable $e) {
                    $throwable = $e;
                }
            });
        } finally {
            if ($proc) {
                $this->stopCliServer($proc);
            }
        }

        if ($throwable) {
            throw $throwable;
        }
    }
}
