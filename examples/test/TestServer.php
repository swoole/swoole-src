<?php
abstract class TestServer
{
    protected $count = array();
    protected $index = array();
    protected $recv_bytes = 0;
    protected $show_lost_package = false;

    const PKG_NUM = 100000;
    const LEN_MIN = 10000;
    const LEN_MAX = 90000;

    /**
     * @var swoole_server
     */
    protected $serv;

    abstract function onReceive($serv, $fd, $from_id, $data);

    function __construct($base = false)
    {
        $mode = $base ? SWOOLE_BASE : SWOOLE_PROCESS;
        $serv = new swoole_server("127.0.0.1", 9501, $mode);
        $serv->on('Connect', [$this, 'onConnect']);
        $serv->on('receive', [$this, '_receive']);
        $serv->on('workerStart', [$this, 'onWorkerStart']);
        $serv->on('Close', [$this, 'onClose']);
        $this->serv = $serv;
    }

    function onConnect($serv, $fd, $from_id)
    {
        $this->count = 0;
    }

    function _receive($serv, $fd, $from_id, $data)
    {
        $this->count++;
        $this->recv_bytes += strlen($data);
        $this->onReceive($serv, $fd, $from_id, $data);
    }

    function onClose($serv, $fd, $from_id)
    {
        echo "Total count={$this->count}, bytes={$this->recv_bytes}\n";
        if ($this->show_lost_package)
        {
            for ($i = 0; $i < self::PKG_NUM; $i++)
            {
                if (!isset($this->index[$i]))
                {
                    echo "lost package#$i\n";
                }
            }
        }
        $this->count = $this->recv_bytes = 0;
        unset($this->index);
        $this->index = array();
    }

    function set($conf)
    {
        $this->serv->set($conf);
    }

    function start()
    {
        $this->serv->start();
    }

    function onWorkerStart($serv, $id)
    {
        //sleep(1);
    }

    static function random()
    {
        return rand(self::LEN_MIN, self::LEN_MAX);
    }
}
