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

define('EMOJI_OK', '✅');
define('EMOJI_SUCCESS', '🚀');
define('EMOJI_ERROR', '❌');
define('EMOJI_WARN', '⚠️');
define('SWOOLE_SOURCE_ROOT', dirname(__DIR__) . '/');
define('SWOOLE_COLOR_RED', 1);
define('SWOOLE_COLOR_GREEN', 2);
define('SWOOLE_COLOR_YELLOW', 3);
define('SWOOLE_COLOR_BLUE', 4);
define('SWOOLE_COLOR_MAGENTA', 5);
define('SWOOLE_COLOR_CYAN', 6);
define('SWOOLE_COLOR_WHITE', 7);

function switch_process()
{
    usleep((USE_VALGRIND ? 100 : 25) * 1000);
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

function get_one_free_port(): int
{
    $hookFlags = Swoole\Runtime::getHookFlags();
    Swoole\Runtime::enableCoroutine(false);
    $server = stream_socket_server('tcp://127.0.0.1:0');
    $name = stream_socket_get_name($server, false);
    $port = (parse_url($name)['port'] ?? -1) ?: -1;
    Swoole\Runtime::enableCoroutine($hookFlags);
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
    $http2 = $options['http2'] ?? false;
    $connect_args = [$domain, $port, $scheme === 'https' || $port === 443];
    if ($http2) {
        $cli = new Swoole\Coroutine\Http2\Client(...$connect_args);
        $request = new Swoole\Http2\Request;
    } else {
        $cli = new Swoole\Coroutine\Http\Client(...$connect_args);
        $request = null;
    }
    $cli->set($options + ['timeout' => 5]);
    if (isset($options['method'])) {
        if ($http2) {
            $request->method = $options['method'];
        } else {
            $cli->setMethod($options['method']);
        }
    }
    if (isset($options['headers'])) {
        if ($http2) {
            $request->headers = $options['headers'];
        } else {
            $cli->setHeaders($options['headers']);
        }
    }
    if (isset($options['data'])) {
        if ($http2) {
            $request->data = $options['data'];
        } else {
            $cli->setData($options['data']);
        }
    }
    if (is_array($options['download'] ?? null)) {
        if ($http2) {
            throw new RuntimeException('HTTP2 not support download');
        }
        $cli->download(...array_values($options['download']));
        return $cli;
    }
    if ($http2) {
        if (!$cli->connect()) {
            throw new RuntimeException("HTTP2 connect {$domain}:{$port} failed: {$cli->errMsg}");
        }
        $request->path = "{$path}{$query}";
        if (!$cli->send($request)) {
            throw new RuntimeException("HTTP2 send request to {$uri} failed: {$cli->errMsg}");
        }
        if (!($response = $cli->recv())) {
            throw new RuntimeException("HTTP2 recv from {$uri} failed: {$cli->errMsg}");
        }
        return [
            'statusCode' => $response->statusCode,
            'headers' => $response->headers,
            'set_cookie_headers' => $response->set_cookie_headers,
            'body' => $response->data
        ];
    } else {
        $redirect_times = $options['redirect'] ?? 3;
        while (true) {
            if (!$cli->execute($path . $query)) {
                throw new RuntimeException("HTTP execute {$uri} failed: {$cli->errMsg}");
            }
            if ($redirect_times-- && ($cli->headers['location'] ?? null) && $cli->headers['location'][0] === '/') {
                $path = $cli->headers['location'];
                $query = '';
                continue;
            }
            break;
        }
        return [
            'statusCode' => $cli->statusCode,
            'headers' => $cli->headers,
            'set_cookie_headers' => $cli->set_cookie_headers,
            'body' => $cli->body
        ];
    }
}

function httpGetStatusCode(string $uri, array $options = [])
{
    return httpRequest($uri, $options)['statusCode'];
}

function httpGetHeaders(string $uri, array $options = [])
{
    return httpRequest($uri, $options)['headers'];
}

function httpGetBody(string $uri, array $options = [])
{
    return httpRequest($uri, $options)['body'];
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

function makeCoTcpClient($host, $port, callable $onConnect = null, callable $onReceive = null)
{
    go(function () use ($host, $port, $onConnect, $onReceive) {
        $cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
        assert($cli->set([
            'open_length_check' => 1,
            'package_length_type' => 'N',
            'package_length_offset' => 0,
            'package_body_offset' => 0,
        ]));
        $r = $cli->connect($host, $port, 1);
        Assert::assert($r);

        if ($onConnect) {
            $onConnect($cli);
        }
        $recv = $cli->recv();
        if ($onReceive) {
            $onReceive($cli, $recv);
        }
    });
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

function check_tcp_port(string $host, int $port): bool
{
    return !!@fsockopen($host, $port);
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
        } else {
            if ($n === 0) {
                // 超时kill -9
                assert(proc_terminate($proc, SIGKILL));
                throw new \RuntimeException("exec $cmd time out");
            } else {
                if ($n > 0) {
                    foreach ($r as $handle) {
                        if ($handle === $pipes[1]) {
                            $_ = &$out;
                        } else {
                            if ($handle === $pipes[2]) {
                                $_ = &$err;
                            } else {
                                $_ = "";
                            }
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

function space(int $length): string
{
    return str_repeat(' ', $length);
}

function camelize(string $uncamelized_words, string $separator = '_'): string
{
    $uncamelized_words = $separator . str_replace($separator, ' ', strtolower($uncamelized_words));
    return ltrim(str_replace(' ', '', ucwords($uncamelized_words)), $separator);
}

function unCamelize(string $camelCaps, string $separator = '_'): string
{
    $camelCaps = preg_replace('/([a-z])([A-Z])/', "\${1}{$separator}\${2}", $camelCaps);
    /* for special case like: PDOPool => pdo_pool */
    $camelCaps = preg_replace('/([A-Z]+)([A-Z][a-z]+)/', "\${1}{$separator}\${2}\${3}", $camelCaps);
    return strtolower($camelCaps);
}

function print_split_line(string $title = '', int $length = 32): void
{
    if ($length % 2 !== 0) {
        $length += 1;
    }
    echo "< {$title} > " . str_repeat('=', $length) . PHP_EOL;
}

function swoole_log(string $content, int $color = 0): void
{
    echo ($color ? "\033[3{$color}m{$content}\033[0m" : $content) . PHP_EOL;
}

function swoole_check(bool $is_ok, string $output): void
{
    if ($is_ok) {
        swoole_ok("{$output} OK!");
    } else {
        swoole_error("{$output} Failed!");
    }
}

function swoole_warn(string ...$args): void
{
    foreach ($args as $arg) {
        swoole_log(EMOJI_WARN . " {$arg}", SWOOLE_COLOR_YELLOW);
    }
}

function swoole_error(string ...$args): void
{
    foreach ($args as $arg) {
        swoole_log(EMOJI_ERROR . " {$arg}", SWOOLE_COLOR_RED);
    }
    exit(255);
}

function swoole_ok(string ...$args): void
{
    foreach ($args as $arg) {
        swoole_log(EMOJI_OK . " {$arg}", SWOOLE_COLOR_GREEN);
    }
}

function swoole_success(string $content): void
{
    swoole_log(
        str_repeat(EMOJI_SUCCESS, 3) . $content . str_repeat(EMOJI_SUCCESS, 3),
        SWOOLE_COLOR_CYAN
    );
    exit(0);
}

function swoole_execute_and_check(array $commands): void
{
    $basename = pathinfo($commands[1] ?? '', PATHINFO_FILENAME);
    echo "[{$basename}]" . PHP_EOL;
    echo "===========  Execute  ==============" . PHP_EOL;
    $command = implode(' ', $commands);
    exec($command, $output, $return_var);
    if (substr($output[0] ?? '', 0, 2) === '#!') {
        array_shift($output);
    }
    echo '> ' . implode("\n> ", $output) . "" . PHP_EOL;
    if ($return_var != 0) {
        swoole_error("Exec {$command} failed with code {$return_var}!");
    }
    echo "=========== Finish Done ============" . PHP_EOL . PHP_EOL;
}

function scan_dir(string $dir, callable $filter = null): array
{
    $files = array_filter(scandir($dir), function (string $file) { return $file[0] !== '.'; });
    array_walk($files, function (&$file) use ($dir) { $file = "{$dir}/{$file}"; });
    return array_values($filter ? array_filter($files, $filter) : $files);
}

function file_size(string $filename, int $decimals = 2): string
{
    $bytes = filesize($filename);
    $sz = 'BKMGTP';
    $factor = (int)floor((strlen($bytes) - 1) / 3);
    return sprintf("%.{$decimals}f", $bytes / pow(1024, $factor)) . $sz[$factor];
}

function swoole_git_files(): array
{
    $root = SWOOLE_SOURCE_ROOT;
    return explode(PHP_EOL, `cd {$root} && git ls-files`);
}

function swoole_source_list(array $ext_list = [], array $excepts = []): array
{
    $source_list = swoole_git_files();
    $source_list = array_filter($source_list, function (string $filename) use ($ext_list, $excepts) {
        $ext_list = $ext_list + [
                'h' => true,
                'c' => true,
                'cc' => true
            ];
        $excepts = $excepts + [
                'core-tests',
                'examples',
                'thirdparty'
            ];
        foreach ($excepts as $except) {
            if (preg_match("/{$except}/", $filename)) {
                return false;
            }
        }
        $ext = pathinfo($filename, PATHINFO_EXTENSION);
        return $ext_list[$ext] ?? false;
    });
    sort($source_list);

    return $source_list;
}
