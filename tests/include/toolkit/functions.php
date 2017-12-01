<?php
function swoole_php_fork($func, $out = false) {
	$process = new swoole_process($func, $out);
	$pid = $process->start();

    register_shutdown_function(
        function ($pid, $process)
        {
            swoole_process::kill($pid);
            $process->wait();
        },
        $pid, $process
    );
	
	return $process;
}

function swoole_unittest_fork($func)
{
    $process = new swoole_process($func, false, false);
    $process->start();

    return $process;
}

function swoole_unittest_wait()
{
    return swoole_process::wait();
}

function makeTcpClient($host, $port, callable $onConnect = null, callable $onReceive = null)
{
    $cli = new \swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
    assert($cli->set([
        'open_length_check' => 1,
        'package_length_type' => 'N',
        'package_length_offset' => 0,
        'package_body_offset' => 0,
    ]));
    $cli->on("connect", function (\swoole_client $cli) use ($onConnect)
    {
        assert($cli->isConnected() === true);
        if ($onConnect)
        {
            $onConnect($cli);
        }
    });
    $cli->on("receive", function (\swoole_client $cli, $recv) use ($onReceive)
    {
        if ($onReceive)
        {
            $onReceive($cli, $recv);
        }
    });
    $cli->on("error", function (\swoole_client $cli)
    {
        swoole_event_exit();
    });
    $cli->on("close", function (\swoole_client $cli)
    {
        swoole_event_exit();
    });
    $cli->connect($host, $port);
}


function opcode_encode($op, $data)
{
    $r = json_encode([$op, $data]);
    assert(json_last_error() === JSON_ERROR_NONE);
    return pack("N", strlen($r) + 4) . $r;
}
function opcode_decode($raw)
{
    $json = substr($raw, 4);
    $r = json_decode($json, true);
    assert(json_last_error() === JSON_ERROR_NONE);
    assert(is_array($r) && count($r) === 2);
    return $r;
}
function kill_self_and_descendant($pid)
{
    if (PHP_OS === "Darwin") {
        return;
    }
    $pids = findDescendantPids($pid);
    foreach($pids as $pid) {
        posix_kill($pid, SIGKILL);
    }
    posix_kill($pid, SIGKILL);
}
/**
 * fork 一个进程把父进程pid通过消息队列传给子进程，延时把父进程干掉
 * @param int $after
 * @param int $sig
 */
function killself_in_syncmode($lifetime = 1000, $sig = SIGKILL) {
    $proc = new \swoole_process(function(\swoole_process $proc) use($lifetime, $sig) {
        $pid = $proc->pop();
        $proc->freeQueue();
        usleep($lifetime * 1000);
        \swoole_process::kill($pid, $sig);
        $proc->exit();
    }, true);
    $proc->useQueue();
    $proc->push(posix_getpid());
    $proc->start();
}
/**
 * 异步模式用定时器干掉自己
 * @param int $lifetime
 * @param int $sig
 * @param callable $cb
 */
function suicide($lifetime, $sig = SIGKILL, callable $cb = null)
{
    swoole_timer_after($lifetime, function() use($lifetime, $sig, $cb) {
        if ($cb) {
            $cb();
        }
        echo "suicide after $lifetime ms\n";
        posix_kill(posix_getpid(), $sig);
    });
}
// 查找某pid的所有子孙pid
function findDescendantPids($pid)
{
    list($pinfo, ) = pstree();
    $y = function($pid) use(&$y, $pinfo) {
        if (isset($pinfo[$pid])) {
            list(, $childs) = $pinfo[$pid];
            $pids = $childs;
            foreach($childs as $child) {
                $pids = array_merge($pids, $y($child));
            }
            return $pids;
        } else {
            return [];
        }
    };
    return $y($pid);
}
/**
 * @return array [pinfo, tree]
 * tree [
 *  ppid
 *  [...child pids]
 * ]
 * list(ppid, array childs) = tree[pid]
 */
function pstree()
{
    $pinfo = [];
    $iter = new DirectoryIterator("/proc");
    foreach($iter as $item) {
        $pid = $item->getFilename();
        if ($item->isDir() && ctype_digit($pid)) {
            $stat = file_get_contents("/proc/$pid/stat");
            $info = explode(" ", $stat);
            $pinfo[$pid] = [intval($info[3]), []/*, $info*/];
        }
    }
    foreach($pinfo as $pid => $info) {
        list($ppid, ) = $info;
        $ppid = intval($ppid);
        $pinfo[$ppid][1][] = $pid;
    }
    $y = function($pid, $path = []) use(&$y, $pinfo) {
        if (isset($pinfo[$pid])) {
            list($ppid, ) = $pinfo[$pid];
            $ppid = $ppid;
            $path[] = $pid;
            return $y($ppid, $path);
        } else {
            return array_reverse($path);
        }
    };
    $tree = [];
    foreach($pinfo as $pid => $info) {
        $path = $y($pid);
        $node = &$tree;
        foreach($path as $id) {
            if (!isset($node[$id])) {
                $node[$id] = [];
            }
            $node = &$node[$id];
        }
    }
    return [$pinfo, $tree];
}
function debug_log($str, $handle = STDERR)
{
    if ($handle === STDERR) {
        $tpl = "\033[31m[%d %s] %s\033[0m\n";
    } else {
        $tpl = "[%d %s] %s\n";
    }
    if (is_resource($handle)) {
        fprintf($handle, $tpl, posix_getpid(), date("Y-m-d H:i:s", time()), $str);
    } else {
        printf($tpl, posix_getpid(), date("Y-m-d H:i:s", time()), $str);
    }
}
function arrayEqual(array $a, array $b, $strict = true)
{
    if (($a && !$b) || (!$a && $b)) {
        return false;
    }
    if ($strict) {
        foreach ($a as $k => $v) {
            if (!array_key_exists($k, $b)) {
                return false;
            }
            if (gettype($v) !== gettype($b[$k])) {
                return false;
            }
            if (is_array($v) && arrayEqual($v, $b[$k]) === false) {
                return false;
            }
        }
        return true;
    } else {
        $aks = array_keys($a);
        $bks = array_keys($b);
        sort($aks);
        sort($bks);
        return $aks === $bks;
    }
}
function get_one_free_port()
{
    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    $ok = socket_bind($socket, "0.0.0.0", 0);
    if (!$ok) {
        return false;
    }
    $ok = socket_listen($socket);
    if (!$ok) {
        return false;
    }
    $ok = socket_getsockname($socket, $addr, $port);
    if (!$ok) {
        return false;
    }
    socket_close($socket);
    return $port;
}
function start_server($file, $host, $port, $redirect_file = "/dev/null", $ext1 = null, $ext2 = null, $debug = false)
{
    $php_executable = getenv('TEST_PHP_EXECUTABLE') ?: PHP_BINARY;
    $cmd_args = getenv('TEST_PHP_ARGS');
    $fdSpec = [
        0 => STDIN,
        1 => STDOUT,
        2 => STDERR,
    ];
    /*if (substr(PHP_OS, 0, 3) == 'WIN') {
        $cmd = "$php_executable $cmd_args $file";
        $opts = ["bypass_shell" => true,  "suppress_errors" => true];
        $handle = proc_open(addslashes($cmd), $fdSpec, $pipes, null, null, $opts);
    } else {
        $cmd = "exec $php_executable $file > $redirect_file 2>&1";
        $handle = proc_open($cmd, $fdSpec, $pipes);
    }*/
    // 必须加exec, 否咋proc_terminate结束不了server进程 ！！！！！！
    if ($debug) {
        $cmd = "exec $php_executable $file $host $port $ext1 $ext2";
        echo "[SHELL_EXEC]".$cmd."\n";
    } else {
        $cmd = "exec $php_executable $file $host $port $ext1 $ext2 > $redirect_file 2>&1";
    }
    // $cmd = "exec $php_executable $file $host $port";
    $handle = proc_open($cmd, $fdSpec, $pipes);
    if ($handle === false) {
        exit(__FUNCTION__ . " fail");
    }
    make_sure_server_listen_success:
    {
        $i = 0;
        $fp = null;
        while (($i++ < 30) && !($fp = @fsockopen($host, $port))) {
            usleep(10000);
        }
        if ($fp) {
            fclose($fp);
        }
    }
// linux上有问题，client端事件循环还没起起来就会先调用这个shutdown回调, 结束了子进程
// 第二个shutdown_function swoole才会把子进程的事件循环起来
//    register_shutdown_function(function() use($handle, $redirect_file) {
//        proc_terminate($handle, SIGTERM);
//        @unlink($redirect_file);
//    });
    return function() use($handle, $redirect_file) {
        // @unlink($redirect_file);
        proc_terminate($handle, SIGTERM);
        swoole_event_exit();
        exit();
    };
}
function fork_exec(callable $fn, $f_stdout = "/dev/null", $f_stderr = null)
{
    $pid = pcntl_fork();
    if ($pid < 0) {
        exit("fork fail");
    }
    if ($pid === 0) {
        fclose(STDOUT);
        $STDOUT = fopen($f_stdout, "w");
        if ($f_stderr !== null) {
            fclose(STDERR);
            $STDERR = fopen($f_stderr, "w");
        }
        $fn();
        exit;
    }
    pcntl_waitpid($pid, $status);
}
/**
 * spawn_exec
 * @param null|string $cmd command
 * @param null|string $input code
 * @param null|int $tv_sec timeout sec
 * @param null|int $tv_usec timeout usec
 * @param null|string $cwd change work dir
 * @param array|null $env env
 * @return array [out, err]
 */
function spawn_exec($cmd, $input = null, $tv_sec = null, $tv_usec = null, $cwd = null, array $env = null)
{
    $out = $err = null;
    $winOpt = ['suppress_errors' => true, 'binary_pipes' => true];
    $proc = proc_open($cmd, [
        0 => ["pipe", "r"],
        1 => ["pipe", "w"],
        2 => ["pipe", "w"],
    ], $pipes, $cwd, $env, $winOpt);
    assert($proc !== false);
    if ($input !== null) {
        $n = fwrite($pipes[0], $input);
        if (strlen($input) !== $n) {
            goto closePipes;
        }
    }
    // 必须关闭
    assert(fclose($pipes[0]));
    unset($pipes[0]);
    // 防止select立即返回, 消耗cpu
    assert(!($tv_sec === 0 && $tv_usec === 0));
    while (true) {
        $r = $pipes;
        $w = null;
        $e = null;
        /* 隐藏被信号或者其他系统调用打断 产生的错误*/
        set_error_handler(function() {});
        $n = @stream_select($r, $w, $e, $tv_sec, $tv_usec);
        restore_error_handler();
        if ($n === false) {
            break;
        } else if ($n === 0) {
            // 超时kill -9
            assert(proc_terminate($proc, SIGKILL));
            throw new \RuntimeException("exec $cmd time out");
        } else if ($n > 0) {
            foreach ($r as $handle) {
                if ($handle === $pipes[1]) {
                    $_ = &$out;
                } else if ($handle === $pipes[2]) {
                    $_ = &$err;
                } else {
                    $_ = "";
                }
                $line = fread($handle, 8192);
                $isEOF = $line === "";
                if ($isEOF) {
                    break 2;
                } else {
                    $_ .= $line;
                }
            }
        }
    }
    closePipes:
    foreach ($pipes as $fd => $pipe) {
        if (is_resource($pipe)) {
            @fclose($pipe);
        }
        unset($pipes[$fd]);
    }
    return [$out, $err];
}

function parent_child($parentFunc, $childFunc)
{
    $pid = pcntl_fork();
    if ($pid < 0)
    {
        echo "ERROR";
        exit;
    }
    if ($pid === 0)
    {
        $childFunc();
        exit;
    }
    else
    {
        $parentFunc($pid);
    }
}

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
class ProcessManager
{
    /**
     * @var swoole_atomic
     */
    protected $atomic;
    protected $alone = false;

    public $parentFunc;
    public $childFunc;
    public $async = false;

    protected $childPid;

    protected $parentFirst = false;

    function __construct()
    {
        $this->atomic = new swoole_atomic(0);
    }

    function setParent(callable $func)
    {
        $this->parentFunc = $func;
    }

    function parentFirst()
    {
        $this->parentFirst = true;
    }

    function childFirst()
    {
        $this->parentFirst = false;
    }

    function setChild(callable $func)
    {
        $this->childFunc = $func;
    }

    //等待信息
    function wait()
    {
        $this->atomic->wait();
    }

    //唤醒等待的进程
    function wakeup()
    {
        $this->atomic->wakeup();
    }

    function runParentFunc($pid = 0)
    {
        return call_user_func($this->parentFunc, $pid);
    }

    function runChildFunc()
    {
        return call_user_func($this->childFunc);
    }

    function fork($func)
    {
        $pid = pcntl_fork();
        if ($pid > 0)
        {
            return $pid;
        }
        elseif ($pid < 0)
        {
            return false;
        }
        else
        {
            call_user_func($func);
            exit;
        }
    }

    /**
     * 杀死子进程
     */
    function kill()
    {
        if (!$this->alone)
        {
            swoole_process::kill($this->childPid);
        }
    }

    function run()
    {
        global $argv, $argc;
        if ($argc > 1)
        {
            if ($argv[1] == 'child')
            {
                $this->alone = true;
                return $this->runChildFunc();
            }
            elseif ($argv[1] == 'parent')
            {
                $this->alone = true;
                return $this->runParentFunc();
            }
        }
        $pid = pcntl_fork();
        if ($this->parentFirst)
        {
            $this->atomic->set(0);
        }
        if ($pid < 0)
        {
            echo "ERROR";
            exit;
        }
        //子进程
        elseif ($pid === 0)
        {
            //等待父进程
            if ($this->parentFirst)
            {
                $this->wait();
            }
            $this->runChildFunc();
            exit;
        }
        //父进程
        else
        {
            $this->childPid = $pid;
            //子进程优先运行，父进程进入等待状态
            if (!$this->parentFirst)
            {
                $this->wait();
            }
            $this->runParentFunc($pid);
            if ($this->async)
            {
                swoole_event::wait();
            }
            pcntl_waitpid($pid, $status);
        }
    }
}


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
class ServerManager
{
    protected $host;
    protected $file;
    public $port;

    function __construct($file)
    {
        if (!is_file($file))
        {
            throw new \Exception("server file [$file] not exists.");
        }
        $this->file = $file;
    }

    function listen($host = '127.0.0.1', $port = 0)
    {
        $this->port = $port == 0 ? get_one_free_port() : $port;
        $this->host = $host;
    }

    function run($debug = false)
    {
        return start_server($this->file, $this->host, $this->port, "/dev/null", null, null, $debug);
    }
}

function debug($var)
{
    var_dump($var);
    exit;
}