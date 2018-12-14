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

function approximate($actual, $expect, float $ratio = 0.1): bool
{
    return $actual * (1 - $ratio) < $expect && $actual * (1 + $ratio) > $expect;
}

function array_random(array $array)
{
    return $array[mt_rand(0, count($array) - 1)];
}

function httpCoroGet(string $uri)
{
    $url_info = parse_url($uri);
    $domain = $url_info['host'];
    $path = $url_info['path'] ?? null ?: '/';
    $port = (int)($url_info['port'] ?? null ?: 80);
    $cli = new Swoole\Coroutine\Http\Client($domain, $port, $port == 443);
    $cli->set(['timeout' => 5]);
    $cli->setHeaders(['Host' => $domain]);
    $cli->get($path);

    return $cli->body;
}

function curlGet($url, $gzip = true)
{
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_HEADER, 0);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    if ($gzip)
    {
        curl_setopt($ch, CURLOPT_HTTPHEADER, array('Accept-Encoding: gzip'));
        curl_setopt($ch, CURLOPT_ENCODING, "gzip");
    }
    $output = curl_exec($ch);
    curl_close($ch);
    return $output;
}

function content_hook_replace(string $content, array $kv_map): string
{
    foreach ($kv_map as $key => $val) {
        $content = str_replace("{{{$key}}}", $val, $content);
    }
    return $content;
}

function tcp_type_length(string $type = 'n'): int
{
    static $map = [
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

    return $map[$type] ?? 0;
}

function tcp_length(string $head, string $type = 'n'): int
{
    return unpack($type, $head)[1];
}

function tcp_pack(string $data, string $type = 'n'): string
{
    return pack($type, strlen($data)) . $data;
}

function tcp_unpack(string $data, string $type = 'n'): string
{
    $type_length = tcp_type_length($type);
    return substr($data, $type_length, unpack($type, substr($data, 0, $type_length))[1]);
}

function var_dump_return(...$data): string
{
    ob_start();
    foreach ($data as $d){
        var_dump($d);
    }
    return ob_get_clean();
}

function get_safe_random(int $length = 32, $original = false): string
{
    $raw = base64_encode(openssl_random_pseudo_bytes($original ? $length : $length * 2));
    if (!$original) {
        $raw = substr(str_replace(['/', '+', '='], '', $raw), 0, $length);
    }
    return $raw;
}

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

function makeTcpClient_without_protocol($host, $port, callable $onConnect = null, callable $onReceive = null)
{
    $cli = new \swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
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
        echo "error\n";
    });
    $cli->on("close", function (\swoole_client $cli)
    {
        echo "close\n";
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
    \swoole_async::set(['enable_coroutine' => false]); // need use exit
    return function() use($handle, $redirect_file) {
        // @unlink($redirect_file);
        proc_terminate($handle, SIGTERM);
        swoole_event_exit();
        exit;
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

class ProcessManager
{
    /**
     * @var swoole_atomic
     */
    protected $atomic;
    protected $alone = false;
    protected $freePorts = [];
    protected $randomData = [];

    public $parentFunc;
    public $childFunc;
    public $async = false;

    protected $childPid;
    protected $childStatus;
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

    function getFreePort(int $index = 0)
    {
        return $this->freePorts[$index];
    }

    /**
     * @param $size
     * @param int $len
     */
    function initRandomData($size, $len = 32)
    {
        for ($n = $size; $n--;) {
            $this->randomData[] = get_safe_random($len);
        }
    }

    /**
     * @param null $index
     * @return mixed
     */
    function getRandomData()
    {
        if (!empty($this->randomData)) {
            return array_shift($this->randomData);
        } else {
            throw new \RuntimeException('Out of the bound');
        }
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
        if (!$this->alone && $this->childPid)
        {
            swoole_process::kill($this->childPid);
        }
    }

    function initFreePorts(int $num = 1)
    {
        if (empty($this->freePorts)) {
            for ($i = $num; $i--;) {
                $this->freePorts[] = get_one_free_port();
            }
        }
    }

    function run()
    {
        global $argv, $argc;
        if ($argc > 1)
        {
            if ($argv[1] == 'child')
            {
                $this->freePorts = [9501];
                $this->alone = true;
                return $this->runChildFunc();
            }
            elseif ($argv[1] == 'parent')
            {
                $this->freePorts = [9501];
                $this->alone = true;
                return $this->runParentFunc();
            }
        }
        $this->initFreePorts();
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
            // if ($this->async)
            // {
            swoole_event_wait();
            // }
            pcntl_waitpid($pid, $status);
            $this->childStatus = $status;
        }
    }

    function expectExitCode($code = 0)
    {
        assert(pcntl_wexitstatus($this->childStatus) == $code);
    }
}

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

class RandStr
{
    const ALPHA     = 1;
    const NUM       = 2;
    const CHINESE   = 4;
    const ALL = self::ALPHA | self::NUM | self::CHINESE;

    const __ALPHA = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const __NUM = "0123456789";
    const __CHINESE2000 = "五于天末开下理事画现玫珠表珍列玉平不来与屯妻到互寺城霜载直进吉协南才垢圾夫无坟增示赤过志地雪支三夺大厅左丰百右历面帮原胡春克太磁砂灰达成顾肆友龙本村枯林械相查可机格析极检构术样档杰棕杨李要权楷七革基苛式牙划或功贡攻匠菜共区芳燕东芝世节切芭药睛睦盯虎止旧占卤贞睡肯具餐眩瞳步眯瞎卢眼皮此量时晨果虹早昌蝇曙遇昨蝗明蛤晚景暗晃显晕电最归紧昆呈叶顺呆呀中虽吕另员呼听吸只史嘛啼吵喧叫啊哪吧哟车轩因困四辊加男轴力斩胃办罗罚较边思轨轻累同财央朵曲由则崭册几贩骨内风凡赠峭迪岂邮凤生行知条长处得各务向笔物秀答称入科秒秋管秘季委么第后持拓打找年提扣押抽手折扔失换扩拉朱搂近所报扫反批且肝采肛胆肿肋肌用遥朋脸胸及胶膛爱甩妥肥脂全会估休代个介保佃仙作伯仍从你信们偿伙亿他分公化钱针然钉氏外旬名甸负儿铁角欠多久匀乐炙锭包凶争色主计庆订度让刘训为高放诉衣认义方说就变这记离良充率闰半关亲并站间部曾商产瓣前闪交六立冰普帝决闻妆冯北汪法尖洒江小浊澡渐没少泊肖兴光注洋水淡学沁池当汉涨业灶类灯煤粘烛炽烟灿烽煌粗粉炮米料炒炎迷断籽娄宽寂审宫军宙客宾家空宛社实宵灾之官字安它怀导居民收慢避惭届必怕愉懈心习悄屡忱忆敢恨怪尼卫际承阿陈耻阳职阵出降孤阴队防联孙耿辽也子限取陛姨寻姑杂毁旭如舅九奶婚妨嫌录灵巡刀好妇妈姆对参戏台劝观矣牟能难允驻驼马邓艰双线结顷红引旨强细纲张绵级给约纺弱纱继综纪弛绿经比烃定守害一在工上是国和的有人我了发以瑟斑晴语伍残封都动什杆舍鞍伏邦悲韭源善着羚磊矿剧页万尤跋森棵酒宁歌臣茹哎莽酣谨甘黄腊垂道植申卡叔趾足虚玻晶暮临象坚界肃梨刊章朝蚕品喊带雷恩闸鸭轰曼黑柬温盆苯苦某荆匡芋棋柑奎霸震积余叙者复怎炸笺简数赣彻覆碧凰皑易肠派汽拿攀势抛看拜哲岳兵肢县甫拥解穆受貌豺豪橡毅衰畏丧众输夷份雁谷苏癸蹬察镜跑软鸟鸣岛印狈逛鲁渔免见杀便誓辩尺州亢亡丹亥孩俯肪激唯截颜冲头均壮兽敝幸夹旁辞滓疗嫉泵永函兆泰康否杯系党灭庶兼播凯撰挖巨启眉媚声蕊恭舔翌翻熟屈齿龄亨蒸滁椰服矛仓她施媳案淄巢扭那丸津食霓骚令通私云爸骤蕴雍幻慈每沸曳王土木目日口田山禾白月金言火已女又干士二十寸雨古犬石厂丁西戈卜曰虫川甲皿竹斤乃八夕文广辛门贝己巳乙尸羽耳臼巴弓阶而种自深农体路正论些资形重战使等合图新还想点其起性斗把里两应制育去气问展意接情油题利压组期毛群次但孔流席运质治位器指建活教统别更真将识先专常造修病老回验很特根团转总任调热改完集毫研尔求精层清确低再证劳被号装单据设场花传判究须青越轮做整即速织书状海斯议般千影推今德差始响觉液维破消试布需胜济效选话片牧备续标存身板述底规走除置配养敌华测准许技床端感非磨往圆照搞族神容亚段算适讲按值美态彪班麦削排该击素密候草何树属市径螺英快坏移材省武培著河京助升抓含苗副谈围射例致酸却短剂宣环落首波践府考刻靠够满住枝局菌周护岩师举元超模贫减扬亩球医校呢稻滑鼓刚写微略范供块套项倒卷创律远初优死毒圈伟控跟裂粮母练塞钢顶策留误粒础故丝焊株院冷弹错散盾视艺版烈零室血缺厘绝富喷柱望盘雄似巩益洲脱投送侧润盖挥距触星松获独混座依未突架冬湿偏纹执寨责阀吃稳硬价努奇预评读背损棉侵厚泥辟卵箱掌氧停溶营终孟待尽俄缩沙退讨奋胞幼迫旋征槽殖握担鲜钻逐脚盐编蜂急伤飞域露核缘游振操甚迅辉异序纸夜乡隶缸念兰映沟吗儒磷插埃燃欢补咱芽瓦倾碳演附耪裔斜灌欧献猪腐请透司危括靛脉囤若尾束暴企穗愈拖牛染既遍锻夏井费访吹荣铜沿替滚旱悟脑措贯藏隙濮徐吴赵陆沈蒋曹唐潘袁郭蔡戴薛姚宋韩谢姜严陶董郑程倪秦邵汤葛俞杜殷龚魏梁崔邹邱彭尹庄卞贾洪盛樊侯邢郁凌仇韦童翟付祁仲宗梅鲍祝谭钟庞乔虞郝傅焦熊浦柏狄裴柳戚房毕翁储聂莫贺茅屠杭尚诸芦鞠廖骆靳詹阮惠桑柯刁柴丛齐喻桂侍舒戎阎宦巫黎涂符厉糜冒钮郎霍甄姬祖卓晓祥萍忠俊斌宏玲勇峰宝霞丽娟敏琴健静福贵勤锦艳莉涛瑞跃仁泉连喜银亮宇慧鹏茂淑芹坤剑君翠彬恒礼侠智浩菊香蓉炳寿圣贤洁耀延翔芬绍琳颖栋巧铭敬淮登鸿宜莲庭孝泽政彩诚崇彦佩宪锡钧劲锋殿希迎堂裕鹤欣汝妹岭沛莹雅佳纯靖蕾俭蔚彤湘绪尧廷锁勋庚嘉伦娥详钦寅冠骏滨威捷亭巍楼呜娜旺晋悦咏焕昭枫琼慎杏仕仪珊桃谦航舜猛卿鼎咸陵镇召敦佐熙遵桥网闽挺菲禄耘锐潮鉴婉塔蚜描粤粱惮慨乌矩疾徊碍戒买笛痛锈锌匆矢溪荤惟陪掩耸棠祭槐憨狙忙辑奉忧飘沫怖悬厌欲谱瘤货蛊赴垣嚎履闯藩遁雀渠探涸滇钡诡弟秩渗痊捏茸诬枪狠弃摇倘贬庙汇肩捎怒帽寄岸搐饼违汕蝎炔擅掖傀闹蜡裸碱奠秉丑倍萧瞒萌歧勒煎谐梳携蛇箕臂皖坍奸胎赌魁患凿傣栈唁晤碑匪翅瘫烤汛狰捍袄瞩碘嗜绰毖瓶疤俺倦冉递葬骇伶擒谴搬睬盎丈粳袋暇颈屉阜邻篓拆脊镭趣鼠疹寐鼻澎椿倔蝴酿辈钨盂购釉逆诛粹凄桅娇菏瑶父抢浮晦拂葫揉壕弊冻笼箩氛舵凹型默闲菩驰啦篡孪瑚蜗午宴驯镶砚怠粥躁豁靡拴睁丘傈腋碟懂皆淤矗浸隘挛咬帛揩瘩妖荡斟疼哥撬铣拨味哇挞迹哈孺桓蚀萄命惫幂渤稗迂瞧菱躺礁贸赶尝郡咖笆扎裤卉割炕砸潦俏饥羹锗赦博衙摆漱畅码砍钎渡绒牢捡痪棍喂辨璃澳饮洼抿窟咯辰隋憋酋绅狱悔厄";
    // const __CHINESE3000 = "啊阿埃挨哎唉哀皑癌蔼矮艾碍爱隘鞍氨安俺按暗岸胺案肮昂盎凹敖熬翱袄傲奥懊澳芭捌扒叭吧笆八疤巴拔跋靶把耙坝霸罢爸白柏百摆佰败拜稗斑班搬扳般颁板版扮拌伴瓣半办绊邦帮梆榜膀绑棒磅蚌镑傍谤苞胞包褒剥薄雹保堡饱宝抱报暴豹鲍爆杯碑悲卑北辈背贝钡倍狈备惫焙被奔苯本笨崩绷甭泵蹦迸逼鼻比鄙笔彼碧蓖蔽毕毙毖币庇痹闭敝弊必辟壁臂避陛鞭边编贬扁便变卞辨辩辫遍标彪膘表鳖憋别瘪彬斌濒滨宾摈兵冰柄丙秉饼炳病并玻菠播拨钵波博勃搏铂箔伯帛舶脖膊渤泊驳捕卜哺补埠不布步簿部怖擦猜裁材才财睬踩采彩菜蔡餐参蚕残惭惨灿苍舱仓沧藏操糙槽曹草厕策侧册测层蹭插叉茬茶查碴搽察岔差诧拆柴豺搀掺蝉馋谗缠铲产阐颤昌猖场尝常长偿肠厂敞畅唱倡超抄钞朝嘲潮巢吵炒车扯撤掣彻澈郴臣辰尘晨忱沉陈趁衬撑称城橙成呈乘程惩澄诚承逞骋秤吃痴持匙池迟弛驰耻齿侈尺赤翅斥炽充冲虫崇宠抽酬畴踌稠愁筹仇绸瞅丑臭初出橱厨躇锄雏滁除楚础储矗搐触处揣川穿椽传船喘串疮窗幢床闯创吹炊捶锤垂春椿醇唇淳纯蠢戳绰疵茨磁雌辞慈瓷词此刺赐次聪葱囱匆从丛凑粗醋簇促蹿篡窜摧崔催脆瘁粹淬翠村存寸磋撮搓措挫错搭达答瘩打大呆歹傣戴带殆代贷袋待逮怠耽担丹单郸掸胆旦氮但惮淡诞弹蛋当挡党荡档刀捣蹈倒岛祷导到稻悼道盗德得的蹬灯登等瞪凳邓堤低滴迪敌笛狄涤翟嫡抵底地蒂第帝弟递缔颠掂滇碘点典靛垫电佃甸店惦奠淀殿碉叼雕凋刁掉吊钓调跌爹碟蝶迭谍叠丁盯叮钉顶鼎锭定订丢东冬董懂动栋侗恫冻洞兜抖斗陡豆逗痘都督毒犊独读堵睹赌杜镀肚度渡妒端短锻段断缎堆兑队对墩吨蹲敦顿囤钝盾遁掇哆多夺垛躲朵跺舵剁惰堕蛾峨鹅俄额讹娥恶厄扼遏鄂饿恩而儿耳尔饵洱二贰发罚筏伐乏阀法珐藩帆番翻樊矾钒繁凡烦反返范贩犯饭泛坊芳方肪房防妨仿访纺放菲非啡飞肥匪诽吠肺废沸费芬酚吩氛分纷坟焚汾粉奋份忿愤粪丰封枫蜂峰锋风疯烽逢冯缝讽奉凤佛否夫敷肤孵扶拂辐幅氟符伏俘服浮涪福袱弗甫抚辅俯釜斧脯腑府腐赴副覆赋复傅付阜父腹负富讣附妇缚咐噶嘎该改概钙盖溉干甘杆柑竿肝赶感秆敢赣冈刚钢缸肛纲岗港杠篙皋高膏羔糕搞镐稿告哥歌搁戈鸽胳疙割革葛格蛤阁隔铬个各给根跟耕更庚羹埂耿梗工攻功恭龚供躬公宫弓巩汞拱贡共钩勾沟苟狗垢构购够辜菇咕箍估沽孤姑鼓古蛊骨谷股故顾固雇刮瓜剐寡挂褂乖拐怪棺关官冠观管馆罐惯灌贯光广逛瑰规圭硅归龟闺轨鬼诡癸桂柜跪贵刽辊滚棍锅郭国果裹过哈骸孩海氦亥害骇酣憨邯韩含涵寒函喊罕翰撼捍旱憾悍焊汗汉夯杭航壕嚎豪毫郝好耗号浩呵喝荷菏核禾和何合盒貉阂河涸赫褐鹤贺嘿黑痕很狠恨哼亨横衡恒轰哄烘虹鸿洪宏弘红喉侯猴吼厚候后呼乎忽瑚壶葫胡蝴狐糊湖弧虎唬护互沪户花哗华猾滑画划化话槐徊怀淮坏欢环桓还缓换患唤痪豢焕涣宦幻荒慌黄磺蝗簧皇凰惶煌晃幌恍谎灰挥辉徽恢蛔回毁悔慧卉惠晦贿秽会烩汇讳诲绘荤昏婚魂浑混豁活伙火获或惑霍货祸击圾基机畸稽积箕肌饥迹激讥鸡姬绩缉吉极棘辑籍集及急疾汲即嫉级挤几脊己蓟技冀季伎祭剂悸济寄寂计记既忌际妓继纪嘉枷夹佳家加荚颊贾甲钾假稼价架驾嫁歼监坚尖笺间煎兼肩艰奸缄茧检柬碱碱拣捡简俭剪减荐槛鉴践贱见键箭件健舰剑饯渐溅涧建僵姜将浆江疆蒋桨奖讲匠酱降蕉椒礁焦胶交郊浇骄娇嚼搅铰矫侥脚狡角饺缴绞剿教酵轿较叫窖揭接皆秸街阶截劫节桔杰捷睫竭洁结解姐戒藉芥界借介疥诫届巾筋斤金今津襟紧锦仅谨进靳晋禁近烬浸尽劲荆兢茎睛晶鲸京惊精粳经井警景颈静境敬镜径痉靖竟竞净炯窘揪究纠玖韭久灸九酒厩救旧臼舅咎就疚鞠拘狙疽居驹菊局咀矩举沮聚拒据巨具距踞锯俱句惧炬剧捐鹃娟倦眷卷绢撅攫抉掘倔爵觉决诀绝均菌钧军君峻俊竣浚郡骏喀咖卡咯开揩楷凯慨刊堪勘坎砍看康慷糠扛抗亢炕考拷烤靠坷苛柯棵磕颗科壳咳可渴克刻客课肯啃垦恳坑吭空恐孔控抠口扣寇枯哭窟苦酷库裤夸垮挎跨胯块筷侩快宽款匡筐狂框矿眶旷况亏盔岿窥葵奎魁傀馈愧溃坤昆捆困括扩廓阔垃拉喇蜡腊辣啦莱来赖蓝婪栏拦篮阑兰澜谰揽览懒缆烂滥琅榔狼廊郎朗浪捞劳牢老佬姥酪烙涝勒乐雷镭蕾磊累儡垒擂肋类泪棱楞冷厘梨犁黎篱狸离漓理李里鲤礼莉荔吏栗丽厉励砾历利僳例俐痢立粒沥隶力璃哩俩联莲连镰廉怜涟帘敛脸链恋炼练粮凉梁粱良两辆量晾亮谅撩聊僚疗燎寥辽潦了撂镣廖料列裂烈劣猎琳林磷霖临邻鳞淋凛赁吝拎玲菱零龄铃伶羚凌灵陵岭领另令溜琉榴硫馏留刘瘤流柳六龙聋咙笼窿隆垄拢陇楼娄搂篓漏陋芦卢颅庐炉掳卤虏鲁麓碌露路赂鹿潞禄录陆戮驴吕铝侣旅履屡缕虑氯律率滤绿峦挛孪滦卵乱掠略抡轮伦仑沦纶论萝螺罗逻锣箩骡裸落洛骆络妈麻玛码蚂马骂嘛吗埋买麦卖迈脉瞒馒蛮满蔓曼慢漫谩芒茫盲氓忙莽猫茅锚毛矛铆卯茂冒帽貌贸么玫枚梅酶霉煤没眉媒镁每美昧寐妹媚门闷们萌蒙檬盟锰猛梦孟眯醚靡糜迷谜弥米秘觅泌蜜密幂棉眠绵冕免勉娩缅面苗描瞄藐秒渺庙妙蔑灭民抿皿敏悯闽明螟鸣铭名命谬摸摹蘑模膜磨摩魔抹末莫墨默沫漠寞陌谋牟某拇牡亩姆母墓暮幕募慕木目睦牧穆拿哪呐钠那娜纳氖乃奶耐奈南男难囊挠脑恼闹淖呢馁内嫩能妮霓倪泥尼拟你匿腻逆溺蔫拈年碾撵捻念娘酿鸟尿捏聂孽啮镊镍涅您柠狞凝宁拧泞牛扭钮纽脓浓农弄奴努怒女暖虐疟挪懦糯诺哦欧鸥殴藕呕偶沤啪趴爬帕怕琶拍排牌徘湃派攀潘盘磐盼畔判叛乓庞旁耪胖抛咆刨炮袍跑泡呸胚培裴赔陪配佩沛喷盆砰抨烹澎彭蓬棚硼篷膨朋鹏捧碰坯砒霹批披劈琵毗啤脾疲皮匹痞僻屁譬篇偏片骗飘漂瓢票撇瞥拼频贫品聘乒坪苹萍平凭瓶评屏坡泼颇婆破魄迫粕剖扑铺仆莆葡菩蒲埔朴圃普浦谱曝瀑期欺栖戚妻七凄漆柒沏其棋奇歧畦崎脐齐旗祈祁骑起岂乞企启契砌器气迄弃汽泣讫掐洽牵扦钎铅千迁签仟谦乾黔钱钳前潜遣浅谴堑嵌欠歉枪呛腔羌墙蔷强抢橇锹敲悄桥瞧乔侨巧鞘撬翘峭俏窍切茄且怯窃钦侵亲秦琴勤芹擒禽寝沁青轻氢倾卿清擎晴氰情顷请庆琼穷秋丘邱球求囚酋泅趋区蛆曲躯屈驱渠取娶龋趣去圈颧权醛泉全痊拳犬券劝缺炔瘸却鹊榷确雀裙群然燃冉染瓤壤攘嚷让饶扰绕惹热壬仁人忍韧任认刃妊纫扔仍日戎茸蓉荣融熔溶容绒冗揉柔肉茹蠕儒孺如辱乳汝入褥软阮蕊瑞锐闰润若弱撒洒萨腮鳃塞赛三叁伞散桑嗓丧搔骚扫嫂瑟色涩森僧莎砂杀刹沙纱傻啥煞筛晒珊苫杉山删煽衫闪陕擅赡膳善汕扇缮墒伤商赏晌上尚裳梢捎稍烧芍勺韶少哨邵绍奢赊蛇舌舍赦摄射慑涉社设砷申呻伸身深娠绅神沈审婶甚肾慎渗声生甥牲升绳省盛剩胜圣师失狮施湿诗尸虱十石拾时什食蚀实识史矢使屎驶始式示士世柿事拭誓逝势是嗜噬适仕侍释饰氏市恃室视试收手首守寿授售受瘦兽蔬枢梳殊抒输叔舒淑疏书赎孰熟薯暑曙署蜀黍鼠属术述树束戍竖墅庶数漱恕刷耍摔衰甩帅栓拴霜双爽谁水睡税吮瞬顺舜说硕朔烁斯撕嘶思私司丝死肆寺嗣四伺似饲巳松耸怂颂送宋讼诵搜艘擞嗽苏酥俗素速粟僳塑溯宿诉肃酸蒜算虽隋随绥髓碎岁穗遂隧祟孙损笋蓑梭唆缩琐索锁所塌他它她塔獭挞蹋踏胎苔抬台泰酞太态汰坍摊贪瘫滩坛檀痰潭谭谈坦毯袒碳探叹炭汤塘搪堂棠膛唐糖倘躺淌趟烫掏涛滔绦萄桃逃淘陶讨套特藤腾疼誊梯剔踢锑提题蹄啼体替嚏惕涕剃屉天添填田甜恬舔腆挑条迢眺跳贴铁帖厅听烃汀廷停亭庭艇通桐酮瞳同铜彤童桶捅筒统痛偷投头透凸秃突图徒途涂屠土吐兔湍团推颓腿蜕褪退吞屯臀拖托脱鸵陀驮驼椭妥拓唾挖哇蛙洼娃瓦袜歪外豌弯湾玩顽丸烷完碗挽晚皖惋宛婉万腕汪王亡枉网往旺望忘妄威巍微危韦违桅围唯惟为潍维苇萎委伟伪尾纬未蔚味畏胃喂魏位渭谓尉慰卫瘟温蚊文闻纹吻稳紊问嗡翁瓮挝蜗涡窝我斡卧握沃巫呜钨乌污诬屋无芜梧吾吴毋武五捂午舞伍侮坞戊雾晤物勿务悟误昔熙析西硒矽晰嘻吸锡牺稀息希悉膝夕惜熄烯溪汐犀檄袭席习媳喜铣洗系隙戏细瞎虾匣霞辖暇峡侠狭下厦夏吓掀锨先仙鲜纤咸贤衔舷闲涎弦嫌显险现献县腺馅羡宪陷限线相厢镶香箱襄湘乡翔祥详想响享项巷橡像向象萧硝霄削哮嚣销消宵淆晓小孝校肖啸笑效楔些歇蝎鞋协挟携邪斜胁谐写械卸蟹懈泄泻谢屑薪芯锌欣辛新忻心信衅星腥猩惺兴刑型形邢行醒幸杏性姓兄凶胸匈汹雄熊休修羞朽嗅锈秀袖绣墟戌需虚嘘须徐许蓄酗叙旭序畜恤絮婿绪续轩喧宣悬旋玄选癣眩绚靴薛学穴雪血勋熏循旬询寻驯巡殉汛训讯逊迅压押鸦鸭呀丫芽牙蚜崖衙涯雅哑亚讶焉咽阉烟淹盐严研蜒岩延言颜阎炎沿奄掩眼衍演艳堰燕厌砚雁唁彦焰宴谚验殃央鸯秧杨扬佯疡羊洋阳氧仰痒养样漾邀腰妖瑶摇尧遥窑谣姚咬舀药要耀椰噎耶爷野冶也页掖业叶曳腋夜液一壹医揖铱依伊衣颐夷遗移仪胰疑沂宜姨彝椅蚁倚已乙矣以艺抑易邑屹亿役臆逸肄疫亦裔意毅忆义益溢诣议谊译异翼翌绎茵荫因殷音阴姻吟银淫寅饮尹引隐印英樱婴鹰应缨莹萤营荧蝇迎赢盈影颖硬映哟拥佣臃痈庸雍踊蛹咏泳涌永恿勇用幽优悠忧尤由邮铀犹油游酉有友右佑釉诱又幼迂淤于盂榆虞愚舆余俞逾鱼愉渝渔隅予娱雨与屿禹宇语羽玉域芋郁吁遇喻峪御愈欲狱育誉浴寓裕预豫驭鸳渊冤元垣袁原援辕园员圆猿源缘远苑愿怨院曰约越跃钥岳粤月悦阅耘云郧匀陨允运蕴酝晕韵孕匝砸杂栽哉灾宰载再在咱攒暂赞赃脏葬遭糟凿藻枣早澡蚤躁噪造皂灶燥责择则泽贼怎增憎曾赠扎喳渣札轧铡闸眨栅榨咋乍炸诈摘斋宅窄债寨瞻毡詹粘沾盏斩辗崭展蘸栈占战站湛绽樟章彰漳张掌涨杖丈帐账仗胀瘴障招昭找沼赵照罩兆肇召遮折哲蛰辙者锗蔗这浙珍斟真甄砧臻贞针侦枕疹诊震振镇阵蒸挣睁征狰争怔整拯正政帧症郑证芝枝支吱蜘知肢脂汁之织职直植殖执值侄址指止趾只旨纸志挚掷至致置帜峙制智秩稚质炙痔滞治窒中盅忠钟衷终种肿重仲众舟周州洲诌粥轴肘帚咒皱宙昼骤珠株蛛朱猪诸诛逐竹烛煮拄瞩嘱主著柱助蛀贮铸筑住注祝驻抓爪拽专砖转撰赚篆桩庄装妆撞壮状椎锥追赘坠缀谆准捉拙卓桌琢茁酌啄着灼浊兹咨资姿滋淄孜紫仔籽滓子自渍字鬃棕踪宗综总纵邹走奏揍租足卒族祖诅阻组钻纂嘴醉最罪尊遵昨左佐柞做作坐座";

    private static $strCache = [];

    public static function gen($len = 10, $type = self::NUM | self::ALPHA) {
        $str = self::getChars($type);
        $strLen = mb_strlen($str);

        $ret = "";
        for ($i = 0; $i < $len; $i++) {
            // non safe rand
            $ret .= mb_substr($str, rand(0, $strLen - 1), 1);
        }
        return $ret;
    }

    static function getBytes($n)
    {
        if (function_exists('openssl_random_pseudo_bytes'))
        {
            return openssl_random_pseudo_bytes($n);
        }
        elseif (function_exists('random_bytes'))
        {
            return random_bytes($n);
        }
        else
        {
            return self::gen($n);
        }
    }

    private static function getChars($mask)
    {
        if (isset(static::$strCache[$mask])) {
            return static::$strCache[$mask];
        }

        $str = "";
        if ($mask & self::NUM) {
            $str .= self::__NUM;
        }

        if ($mask & self::ALPHA) {
            $str .= self::__ALPHA;
        }

        if ($mask & self::CHINESE) {
            $str .= self::__CHINESE2000;
        }

        if ($str === "") {
            $str .= self::NUM . self::ALPHA;
        }

        static::$strCache[$mask] = $str;
        return $str;
    }
}

class TcpStat
{
    const SS_NETSTAT_TCP_STATE_MAP = [
        "established"   => "ESTABLISHED",
        "syn-sent"      => "SYN_SENT",
        "syn-recv"      => "SYN_RCVD",
        "fin-wait-1"    => "FIN_WAIT_1",
        "fin-wait-2"    => "FIN_WAIT_2",
        "time-wait"     => "TIME_WAIT",
        "closed"        => "CLOSED",
        "close-wait"    => "CLOSE_WAIT",
        "last-ack"      => "LAST_ACK",
        "listen"        => "LISTEN",
        "closing"       => "CLOSING",
    ];

    public static function xCount($path)
    {
        if (PHP_OS === "Darwin") {
            $n = `netstat -x | grep $path | wc -l`;
            return intval(trim($n));
        } else {
            $n = `ss -x src $path | wc -l`;
            return intval(trim($n)) - 1;
        }
    }

    public static function count($host, $port, $states = ["established", "time-wait", "close-wait"]) {
        if (!ip2long($host)) {
            $host = gethostbyname($host);
        }

        $pipe = "wc -l";
        $func = PHP_OS === "Darwin" ?  "netstat" : "ss";
        $states = static::fmtTcpState($states, $func);

        $info = [];
        foreach ($states as $state) {
            $ret = call_user_func([static::class, $func], $host, $port, $state, $pipe);
            $info[$state] = intval(trim($ret)) - 1;
        }

        return $info;
    }

    private static function netstat($host, $port, $state, $pipe = "")
    {
        if ($pipe) {
            $pipe = " | $pipe";
        }
        // $4 src $5 dst $6 stats
        return `netstat -an | awk '(\$5 == "$host.$port" && \$6 == "$state") || NR==2  {print \$0}' $pipe`;
    }

    private static function ss($host, $port, $state, $pipe = "")
    {
        if ($pipe) {
            $pipe = " | $pipe";
        }
        return `ss state $state dst $host:$port $pipe`;
    }

    private static function fmtTcpState(array $states, $type)
    {
        $from = $to = [];
        if ($type === "ss") {
            $to = static::SS_NETSTAT_TCP_STATE_MAP;
            $from = array_flip($to);
        } else if ($type === "netstat") {
            $from = static::SS_NETSTAT_TCP_STATE_MAP;
            $to = array_flip($from);
        }

        $ret = [];
        foreach ($states as $state) {
            if (isset($to[$state])) {
                $ret[] = $state;
            } else if (isset($from[$state])) {
                $ret[] = $from[$state];
            }
        }
        return $ret;
    }
}