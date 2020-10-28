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
 | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
 +----------------------------------------------------------------------+
 */

namespace SwooleTest;

use Swoole;
use swoole_atomic;

class ProcessManager
{
    /**
     * @var swoole_atomic
     */
    protected $atomic;
    protected $alone = false;
    protected $freePorts = [];
    protected $randomFunc = 'get_safe_random';
    protected $randomData = [[]];

    /**
     * wait wakeup 1s default
     */
    protected $waitTimeout = 1.0;

    public $parentFunc;
    public $childFunc;
    public $async = false;
    public $useConstantPorts = false;

    protected $childPid;
    protected $childStatus = 255;
    protected $expectExitSignal = [0, SIGTERM];
    protected $parentFirst = false;
    /**
     * @var Swoole\Process
     */
    protected $childProcess;

    public function __construct()
    {
        $this->atomic = new Swoole\Atomic(0);
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
            throw new \RuntimeException('Out of the bound');
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
        if (!$this->alone && $this->childPid) {
            if ($force || (!@Swoole\Process::kill($this->childPid) && swoole_errno() !== PCNTL_ESRCH)) {
                if (!@Swoole\Process::kill($this->childPid, SIGKILL) && swoole_errno() !== PCNTL_ESRCH) {
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
                return $this->runChildFunc();
            } elseif ($argv[1] == 'parent') {
                return $this->runParentFunc();
            } else {
                throw new \RuntimeException("bad parameter \$1\n");
            }
        }
        $this->initFreePorts();
        $this->childProcess = new Swoole\Process(function () {
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
        Swoole\Event::wait();
        $waitInfo = Swoole\Process::wait(true);
        $this->childStatus = $waitInfo['code'];
        if (!in_array($waitInfo['signal'], $this->expectExitSignal)) {
            throw new \RuntimeException("Unexpected exit code {$waitInfo['signal']}");
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
        assert(in_array($this->childStatus, $code), "unexpected exit code {$this->childStatus}");
    }

    public function setExpectExitSignal($signal = 0)
    {
        if (!is_array($signal)) {
            $signal = [$signal];
        }
        $this->expectExitSignal = $signal;
    }
}
