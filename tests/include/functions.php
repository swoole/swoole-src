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

require_once __DIR__ . '/config.php';

function switch_process()
{
    usleep((USE_VALGRIND ? 100 : 10) * 1000);
}

function clear_php()
{
    `ps -A | grep php | grep -v phpstorm | grep -v 'run-tests' | awk '{print $1}' | xargs kill -9 > /dev/null 2>&1`;
}

function top(int $pid)
{
    static $available;
    $available = $available ?? !(IS_MAC_OS || empty(`top help 2>&1 | grep -i usage`));
    if (!$available) {
        return false;
    }
    do {
        $top = @`top -b -n 1 -p {$pid}`;
        if (empty($top)) {
            trigger_error("top {$pid} failed: " . swoole_strerror(swoole_errno()), E_USER_WARNING);
            return false;
        } else {
            break;
        }
    } while (true);
    $top = explode("\n", $top);
    $top = array_combine(preg_split('/\s+/', trim($top[6])), preg_split('/\s+/', trim($top[7])));
    return $top;
}

function is_busybox_ps(): bool
{
    static $bool;
    $bool = $bool ?? !empty(`ps --help 2>&1 | grep -i busybox`);
    return $bool;
}

function kill_process_by_name(string $name)
{
    shell_exec('ps aux | grep "' . $name . '" | grep -v grep | awk \'{ print $' . (is_busybox_ps() ? '1' : '2') . '}\' | xargs kill');
}

function get_process_pid_by_name(string $name): bool
{
    return (int)shell_exec('ps aux | grep "' . $name . '" | grep -v grep | awk \'{ print $' . (is_busybox_ps() ? '1' : '2') . '}\'');
}

function is_musl_libc(): bool
{
    static $bool;
    $bool = $bool ?? !empty(`ldd 2>&1 | grep -i musl`);
    return $bool;
}

function get_one_free_port()
{
    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    if (!socket_bind($socket, "0.0.0.0", 0)) {
        return false;
    }
    if (!socket_listen($socket)) {
        return false;
    }
    if (!socket_getsockname($socket, $addr, $port)) {
        return false;
    }
    socket_close($socket);
    return $port;
}

function get_one_free_port_coro()
{
    $socket = new Co\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    $socket->bind('0.0.0.0');
    $socket->listen();
    $port = $socket->getsockname()['port'];
    $socket->close();
    return $port;
}

function set_socket_coro_buffer_size(Swoole\Coroutine\Socket $cosocket, int $size)
{
    $cosocket->setOption(SOL_SOCKET, SO_SNDBUF, $size);
    $cosocket->setOption(SOL_SOCKET, SO_RCVBUF, $size);
}

function approximate($expect, $actual, float $ratio = 0.1): bool
{
    $ret = $actual * (1 - $ratio) < $expect && $actual * (1 + $ratio) > $expect;
    if (!$ret) {
        trigger_error("approximate: expect {$expect}, but got {$actual}\n", E_USER_WARNING);
    }
    return $ret;
}

function time_approximate($expect, $actual, float $ratio = 0.1)
{
    return USE_VALGRIND || approximate($expect, $actual, $ratio);
}

function ms_random(float $a, float $b): float
{
    return mt_rand($a * 1000, $b * 1000) / 1000;
}

function string_pop_front(string &$s, int $length): string
{
    $r = substr($s, 0, $length);
    $s = substr($s, $length);
    return $r;
}

function array_random(array $array)
{
    return $array[mt_rand(0, count($array) - 1)];
}

function phpt_echo(...$args)
{
    global $argv;
    if (substr($argv[0], -5) === '.phpt') {
        foreach ($args as $arg) {
            echo $arg;
        }
    }
}

function phpt_var_dump(...$args)
{
    global $argv;
    if (substr($argv[0], -5) === '.phpt') {
        var_dump(...$args);
    }
}

function httpRequest(string $uri, array $options = [])
{
    $url_info = parse_url($uri);
    $scheme = $url_info['scheme'] ?? 'http';
    $domain = $url_info['host'] ?? '127.0.0.1';
    $path = $url_info['path'] ?? null ?: '/';
    $query = $url_info['query'] ?? null ? "?{$url_info['query']}" : '';
    $port = (int)($url_info['port'] ?? null ?: 80);
    $cli = new Swoole\Coroutine\Http\Client($domain, $port, $scheme === 'https' || $port === 443);
    $cli->set($options + ['timeout' => 5]);
    if (isset($options['method'])) {
        $cli->setMethod($options['method']);
    }
    if (isset($options['headers'])) {
        $cli->setHeaders($options['headers']);
    }
    if (isset($options['data'])) {
        $cli->setData($options['data']);
    }
    $redirect_times = $options['redirect'] ?? 3;
    while (true) {
        $cli->execute($path . $query);
        if ($redirect_times-- && ($cli->headers['location'] ?? null) && $cli->headers['location'][0] === '/') {
            $path = $cli->headers['location'];
            $query = '';
            continue;
        }
        break;
    }
    return $cli;
}

function httpGetStatusCode(string $uri, array $options = [])
{
    return httpRequest($uri, $options)->statusCode;
}

function httpGetHeaders(string $uri, array $options = [])
{
    return httpRequest($uri, $options)->headers;
}

function httpGetBody(string $uri, array $options = [])
{
    return httpRequest($uri, $options)->body;
}

function content_hook_replace(string $content, array $kv_map): string
{
    foreach ($kv_map as $key => $val) {
        $content = str_replace("{{{$key}}}", $val, $content);
    }
    return $content;
}

function tcp_length_types(): array
{
    return [
        'c' => 1,
        'C' => 1,
        's' => 2,
        'S' => 2,
        'n' => 2,
        'v' => 2,
        'l' => 4,
        'L' => 4,
        'N' => 4,
        'V' => 4,
    ];
}

function tcp_type_length(string $type = 'n'): int
{
    $map = tcp_length_types();
    if (strlen($type) === 1) {
        return $map[$type] ?? 0;
    } else {
        $len = 0;
        for ($n = 0; $n < strlen($type); $n++) {
            $len += $map[$type[$n]] ?? 0;
        }
        return $len;
    }
}

function tcp_head(int $length, string $type = 'n'): string
{
    return pack($type, $length);
}

function tcp_pack(string $data, string $type = 'n'): string
{
    return pack($type, strlen($data)) . $data;
}

function tcp_length(string $head, string $type = 'n'): int
{
    return unpack($type, $head)[1];
}

function tcp_unpack(string $data, string $type = 'n'): string
{
    $type_length = tcp_type_length($type);
    return substr($data, $type_length, unpack($type, substr($data, 0, $type_length))[1]);
}

function var_dump_return(...$data): string
{
    ob_start();
    foreach ($data as $d) {
        var_dump($d);
    }
    return ob_get_clean();
}

function get_safe_random(int $length = 32, $original = false): string
{
    $raw = base64_encode(RandStr::getBytes($original ? $length : $length * 2));
    if (!$original) {
        $raw = substr(str_replace(['/', '+', '='], '', $raw), 0, $length);
    }
    return $raw;
}

function get_big_random(int $length = 1024 * 1024)
{
    if ($length < 1024 * 1024 || $length % 1024 !== 0) {
        throw new InvalidArgumentException('Invalid length ' . $length);
    }
    return str_repeat(get_safe_random(1024), $length / 1024);
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
    $cli->on("connect", function (\swoole_client $cli) use ($onConnect) {
        Assert::true($cli->isConnected());
        if ($onConnect) {
            $onConnect($cli);
        }
    });
    $cli->on("receive", function (\swoole_client $cli, $recv) use ($onReceive) {
        if ($onReceive) {
            $onReceive($cli, $recv);
        }
    });
    $cli->on("error", function (\swoole_client $cli) {
        swoole_event_exit();
    });
    $cli->on("close", function (\swoole_client $cli) {
        swoole_event_exit();
    });
    $cli->connect($host, $port);
}

function makeTcpClient_without_protocol($host, $port, callable $onConnect = null, callable $onReceive = null)
{
    $cli = new \swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
    $cli->on("connect", function (\swoole_client $cli) use ($onConnect) {
        Assert::true($cli->isConnected());
        if ($onConnect) {
            $onConnect($cli);
        }
    });
    $cli->on("receive", function (\swoole_client $cli, $recv) use ($onReceive) {
        if ($onReceive) {
            $onReceive($cli, $recv);
        }
    });
    $cli->on("error", function (\swoole_client $cli) {
        echo "error\n";
    });
    $cli->on("close", function (\swoole_client $cli) {
        echo "close\n";
    });
    $cli->connect($host, $port);
}

function opcode_encode($op, $data)
{
    $r = json_encode([$op, $data]);
    Assert::same(json_last_error(), JSON_ERROR_NONE);
    return pack("N", strlen($r) + 4) . $r;
}

function opcode_decode($raw)
{
    $json = substr($raw, 4);
    $r = json_decode($json, true);
    Assert::same(json_last_error(), JSON_ERROR_NONE);
    assert(is_array($r) && count($r) === 2);
    return $r;
}

function kill_self_and_descendant($pid)
{
    if (PHP_OS === "Darwin") {
        return;
    }
    $pids = findDescendantPids($pid);
    foreach ($pids as $pid) {
        posix_kill($pid, SIGKILL);
    }
    posix_kill($pid, SIGKILL);
}

/**
 * fork 一个进程把父进程pid通过消息队列传给子进程，延时把父进程干掉
 * @param int $after
 * @param int $sig
 */
function killself_in_syncmode($lifetime = 1000, $sig = SIGKILL)
{
    $proc = new Swoole\Process(function (Swoole\Process $proc) use ($lifetime, $sig) {
        $pid = $proc->pop();
        $proc->freeQueue();
        usleep($lifetime * 1000);
        Swoole\Process::kill($pid, $sig);
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
 * @return mixed
 */
function suicide($lifetime, $sig = SIGKILL, callable $cb = null)
{
    return swoole_timer_after($lifetime, function () use ($lifetime, $sig, $cb) {
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
    list($pinfo,) = pstree();
    $y = function ($pid) use (&$y, $pinfo) {
        if (isset($pinfo[$pid])) {
            list(, $childs) = $pinfo[$pid];
            $pids = $childs;
            foreach ($childs as $child) {
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
    foreach ($iter as $item) {
        $pid = $item->getFilename();
        if ($item->isDir() && ctype_digit($pid)) {
            $stat = file_get_contents("/proc/$pid/stat");
            $info = explode(" ", $stat);
            $pinfo[$pid] = [intval($info[3]), []/*, $info*/];
        }
    }
    foreach ($pinfo as $pid => $info) {
        list($ppid,) = $info;
        $ppid = intval($ppid);
        $pinfo[$ppid][1][] = $pid;
    }
    $y = function ($pid, $path = []) use (&$y, $pinfo) {
        if (isset($pinfo[$pid])) {
            list($ppid,) = $pinfo[$pid];
            $ppid = $ppid;
            $path[] = $pid;
            return $y($ppid, $path);
        } else {
            return array_reverse($path);
        }
    };
    $tree = [];
    foreach ($pinfo as $pid => $info) {
        $path = $y($pid);
        $node = &$tree;
        foreach ($path as $id) {
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

function check_tcp_port($ip, $port)
{
    $sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    socket_set_nonblock($sock);
    socket_connect($sock, $ip, $port);
    socket_set_block($sock);
    $r = [$sock];
    $w = [$sock];
    $f = [$sock];
    $status = socket_select($r, $w, $f, 5);
    socket_close($sock);

    return $status;
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
        echo "[SHELL_EXEC]" . $cmd . "\n";
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
    swoole_async_set(['enable_coroutine' => false]); // need use exit
    return function () use ($handle, $redirect_file) {
        // @unlink($redirect_file);
        proc_terminate($handle, SIGTERM);
        swoole_event_exit();
        exit;
    };
}

function swoole_fork_exec(callable $fn, bool $redirect_stdin_and_stdout = false, int $pipe_type = SOCK_DGRAM, bool $enable_coroutine = false)
{
    $process = new Swoole\Process(...func_get_args());
    if (!$process->start()) {
        return false;
    }
    return $process::wait();
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
        set_error_handler(function () {
        });
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
    if ($pid < 0) {
        echo "ERROR";
        exit;
    }
    if ($pid === 0) {
        $childFunc();
        exit;
    } else {
        $parentFunc($pid);
    }
}

function readfile_with_lock($file)
{
    $fp = fopen($file, "r+");
    flock($fp, LOCK_SH);
    $data = '';
    while (!feof($fp)) {
        $data .= fread($fp, 8192);
    }
    fclose($fp);
    return $data;
}