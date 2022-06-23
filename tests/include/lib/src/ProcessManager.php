<?php
/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2017 The Swoole Group                             |
 +----------------------------------------------------------------------+
 | This source file is subject to version 2.0 of the Apache license,    |
 | that is bundled with this package in the file LICENSE, and is        |
 | available through the world-wide-web at the following url:           |
 | http://www.apache.org/licenses/LICENSE-2.0.html                      |
 | If you did not receive a copy of the Apache2.0 license and are unable|
 | to obtain it through the world-wide-web, please send a note to       |
 | license@swoole.com so we can mail you a copy immediately.            |
 +----------------------------------------------------------------------+
 | Author: Tianfeng Han  <rango@swoole.com>                             |
 +----------------------------------------------------------------------+
 */

namespace SwooleTest;

use RuntimeException;
use Swoole\Atomic;
use Swoole\Event;
use Swoole\Process;

class ProcessManager
{
    /**
     * @var Atomic
     */
    protected $atomic;
    protected $alone = false;
    protected $onlyChild = false;
    protected $onlyParent = false;
    protected $freePorts = [];
    protected $randomFunc = 'get_safe_random';
    protected $randomData = [[]];
    protected $randomDataArray = [];

    /**
     * wait wakeup 1s default
     */
    protected $waitTimeout = 1.0;

    public $parentFunc;
    public $childFunc;
    public $async = false;
    public $useConstantPorts = false;

    protected $childPid;
    protected $childExitStatus = 255;
    protected $expectExitSignal = [0, SIGTERM];
    protected $parentFirst = false;
    protected $killed = false;
    /**
     * @var Process
     */
    protected $childProcess;
    protected $logFileHandle;

    public function __construct()
    {
        $this->atomic = new Atomic(0);
    }

    public function setParent(callable $func)
    {
        $this->parentFunc = $func;
    }

    public function parentFirst()
    {
        $this->parentFirst = true;
    }

    public function childFirst()
    {
        $this->parentFirst = false;
    }

    public function setChild(callable $func)
    {
        $this->childFunc = $func;
    }

    public function getChildPid(): int
    {
        return $this->childPid;
    }

    public function setWaitTimeout(int $value)
    {
        $this->waitTimeout = $value;
    }

    //等待信息
    public function wait()
    {
        if ($this->alone || $this->waitTimeout == 0) {
            return false;
        }
        return $this->atomic->wait($this->waitTimeout);
    }

    //唤醒等待的进程
    public function wakeup()
    {
        if ($this->alone) {
            return false;
        }
        return $this->atomic->wakeup();
    }

    public function runParentFunc($pid = 0)
    {
        if (!$this->parentFunc) {
            return (function () { $this->kill(); })();
        } else {
            return call_user_func($this->parentFunc, $pid);
        }
    }

    public function setLogFile($file)
    {
        $this->logFileHandle = fopen($file, "a+");
    }

    public function writeLog($msg)
    {
        fwrite($this->logFileHandle, $msg . PHP_EOL);
    }

    /**
     * @param int $index
     * @return mixed
     */
    public function getFreePort($index = 0)
    {
        return $this->freePorts[$index];
    }

    public function setRandomFunc($func)
    {
        $this->randomFunc = $func;
    }

    public function initRandomData(int $size, int $len = null)
    {
        $this->initRandomDataEx(1, $size, $len);
    }

    /**
     * 生成一个随机字节组成的数组
     * @param int $n
     * @param int $len 默认为0，表示随机产生长度
     * @param bool $base64
     * @throws \Exception
     */
    public function initRandomDataArray($n = 1, $len = 0, bool $base64 = false)
    {
        while ($n--) {
            if ($len == 0) {
                $len = rand(1024, 1 * 1024 * 1024);
            }
            $bytes = random_bytes($len);
            $this->randomDataArray[] = $base64 ? base64_encode($bytes) : $bytes;
        }
    }

    /**
     * @param $index
     * @return mixed
     */
    public function getRandomDataElement(int $index = 0)
    {
        if (!isset($this->randomDataArray[$index])) {
            throw new RuntimeException("out of array");
        }
        return $this->randomDataArray[$index];
    }

    public function getRandomData()
    {
        return $this->getRandomDataEx(0);
    }

    public function getRandomDataSize(): int
    {
        return $this->getRandomDataSizeEx(0);
    }

    public function initRandomDataEx(int $block_num, int $size, ...$arguments)
    {
        $arguments = array_reverse($arguments);
        $shift = 0;
        foreach ($arguments as $index => $argument) {
            if ($argument === null) {
                $shift++;
            } else {
                break;
            }
        }
        while ($shift--) {
            array_shift($arguments);
        }
        $arguments = array_reverse($arguments);
        $func = $this->randomFunc;
        for ($b = 0; $b < $block_num; $b++) {
            for ($n = $size; $n--;) {
                $this->randomData[$b][] = $func(...$arguments);
            }
        }
    }

    public function getRandomDataEx(int $block_id)
    {
        if (!empty($this->randomData[$block_id])) {
            return array_shift($this->randomData[$block_id]);
        } else {
            throw new RuntimeException('Out of the bound');
        }
    }

    public function getRandomDataSizeEx(int $block_id): int
    {
        return count($this->randomData[$block_id]);
    }

    public function runChildFunc()
    {
        return call_user_func($this->childFunc);
    }

    /**
     *  Kill Child Process
     * @param bool $force
     */
    public function kill(bool $force = false)
    {
        if (!defined('PCNTL_ESRCH')) {
            define('PCNTL_ESRCH', 3);
        }
        if (!$this->alone and !$this->killed and $this->childPid) {
            $this->killed = true;
            if ($force || (!@Process::kill($this->childPid) && swoole_errno() !== PCNTL_ESRCH)) {
                if (!@Process::kill($this->childPid, SIGKILL) && swoole_errno() !== PCNTL_ESRCH) {
                    exit('KILL CHILD PROCESS ERROR');
                }
            }
        }
    }

    public function initFreePorts(int $num = 1)
    {
        for ($i = $num; $i--;) {
            $this->freePorts[] = $this->useConstantPorts ? (9500 + $num - $i + count($this->freePorts)) : get_one_free_port();
        }
    }

    public function initFreeIPv6Ports(int $num = 1)
    {
        for ($i = $num; $i--;) {
            $this->freePorts[] = $this->useConstantPorts ? (9500 + $num - $i + count($this->freePorts)) : get_one_free_port_ipv6();
        }
    }

    public function run($redirectStdout = false)
    {
        global $argv, $argc;
        if ($argc > 1) {
            $this->useConstantPorts = true;
            $this->alone = true;
            $this->initFreePorts();
            if ($argv[1] == 'child') {
                $this->onlyChild = true;
            } elseif ($argv[1] == 'parent') {
                $this->onlyParent = true;
            } else {
                throw new RuntimeException("bad parameter \$1\n");
            }
        }
        $this->initFreePorts();
        if ($this->alone) {
            if ($this->onlyChild) {
                return $this->runChildFunc();
            } elseif ($this->onlyParent) {
                return $this->runParentFunc();
            }
            $this->alone = false;
        }

        $this->childProcess = new Process(function () {
            if ($this->parentFirst) {
                $this->wait();
            }
            $this->runChildFunc();
            exit;
        }, $redirectStdout, $redirectStdout);
        if (!$this->childProcess || !$this->childProcess->start()) {
            exit("ERROR: CAN NOT CREATE PROCESS\n");
        }
        register_shutdown_function(function () {
            $this->kill();
        });
        if (!$this->parentFirst) {
            $this->wait();
        }
        $this->runParentFunc($this->childPid = $this->childProcess->pid);
        Event::wait();
        $waitInfo = Process::wait(true);
        $this->childExitStatus = $waitInfo['code'];
        if (!in_array($waitInfo['signal'], $this->expectExitSignal)) {
            throw new RuntimeException("Unexpected exit code {$waitInfo['signal']}");
        }

        return true;
    }

    public function getChildOutput()
    {
        $this->childProcess->setBlocking(false);
        $output = '';
        while (1) {
            $data = @$this->childProcess->read();
            if (!$data) {
                break;
            } else {
                $output .= $data;
            }
        }
        return $output;
    }

    public function expectExitCode($code = 0)
    {
        if (!is_array($code)) {
            $code = [$code];
        }
        if (!in_array($this->childExitStatus, $code)) {
            throw new RuntimeException("Unexpected exit code {$this->childExitStatus}");
        }
    }

    function getChildExitStatus() {
        return $this->childExitStatus;
    }

    public function setExpectExitSignal($signal = 0)
    {
        if (!is_array($signal)) {
            $signal = [$signal];
        }
        $this->expectExitSignal = $signal;
    }

    static function exec(callable $fn)
    {
        $pm = new static();
        $pm->setWaitTimeout(0);
        $pm->parentFunc = function () {
        };
        $pm->childFunc = function () use ($pm, $fn) {
            $fn($pm);
        };
        $pm->childFirst();
        $pm->run(true);

        return $pm;
    }
}
