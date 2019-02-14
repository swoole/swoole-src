<?php
//php co_http_client.php -c 100 -n 10000 -s http://172.16.0.34:9501/query_path?query_string
ini_set("memory_limit","512M");
co::set(array(
    'max_coroutine' => 50000,
));

$shortopts = "c:";
$shortopts .= "n:";
$shortopts .= "s:";

$opt = getopt($shortopts);
//并发数量
if(!isset($opt['c'])) exit("require -c [process_num]. ep: -c 100\n");
if(!isset($opt['n'])) exit("require -n [request_num]. ep: -n 10000\n");
if(!isset($opt['s'])) exit("require -s [server_url]. ep: -s http://127.0.0.1:9999\n");

$bc = new Swoole_Benchmark(trim($opt['f']));
$bc->c = (int)$opt['c'];
$bc->n = (int)$opt['n'];
$bc->server_url = trim($opt['s']);
$bc->server_config = parse_url($bc->server_url);
$bc->send_data = str_repeat("A", 100);//post data
$bc->test_time = empty($opt['t']) ? 0 : strtotime($opt['t']);

//域名只解析一次
if(!filter_var($bc->server_config['host'], FILTER_FLAG_IPV4) && $bc->server_config['host'])
{
    $bc->server_config['host'] = gethostbyname($bc->server_config['host']);
}
var_dump($bc->server_config);exit;
$bc->read_len = 65536;
if(!empty($opt['p'])) $bc->show_detail = true;
$bc->run();
$bc->report();

class Swoole_Benchmark
{
    public $test_func;
    public $c;
    public $n;
    public $req_num;
    public $vars;
    public $test_time;
    public $server_url;
    public $server_config;
    public $send_data;
    public $read_len;
    public $time_start;
    public $time_end;

    public $lost = 0;
    public $success = 0;

    public $show_detail = false;
    public $max_write_time = 0;
    public $max_read_time = 0;
    public $max_conn_time = 0;

    function __construct($func)
    {
        $this->test_func = $func;
    }

    function run()
    {
        $this->time_start = microtime(true);
        $chan = new Swoole\Coroutine\Channel($this->n);

        for ($i = 0; $i < $this->n; $i++) {
            go(function () use ($chan, $path) {
                $cli = new Co\http\Client(
                    $this->server_config['host'],
                    $this->server_config['port']
                );
                $cli->set(['timeout' => 2]);
                $cli->get('/index.php');
                if (!empty($cli->body)) {
                    $this->success ++;
                } else {
                    $this->lost ++;
                }
                if ($i/1000 == 0) {
                    echo "";
                }
            });
        }
        swoole_event::wait();
        $this->time_end = microtime(true);
    }

    function report()
    {
        $lost = $this->lost;
        $usetime = $this->time_end - $this->time_start;
        //并发量
        echo "concurrency:\t".$this->c."\n";
        //请求量
        echo "request num:\t".$this->n."\n";
        //请求量
        echo "lost num:\t".$lost."\n";
        //请求量
        echo "success num:\t".($this->n-$lost)."\n";
        //总时间
        echo "total time:\t".substr($usetime,0,5)."\n";
        //每秒处理能力
        echo "req per second:\t".intval($this->n/$usetime)."\n";
        //每次请求平均时间ms
        echo "one req use(ms):\t".substr($usetime/$this->n*1000,0,5)."\n";
    }
}
