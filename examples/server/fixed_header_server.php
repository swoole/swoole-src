<?php
define('PID_FILE_NAME', '/tmp/swoole_server.pid');

$serv = new FixedHeaderServer();
$serv->run('0.0.0.0', 9504);

class FixedHeaderServer
{
    protected $buffer = array();
    protected $length = array();

    /**
     * @var swoole_server
     */
    protected $serv;

    const MAX_PACKAGE_LEN  = 8000000;

    function onPackage($fd, $pkg)
    {
        $this->current_fd = $fd;
        var_dump($pkg);
        $resp = "hello world";
        $this->serv->send($fd, $resp);
        $this->current_fd = '';
    }
    
    function onReceive($serv, $fd, $from_id, $data)
    {
    	echo "package".substr($data, -4, 4)." length=". (strlen($data) - 2)."\n";
    }

    function onReceive_unpack_php($serv, $fd, $from_id, $data)
    {
        if (empty($this->buffer[$fd]))
        {
            $this->buffer[$fd] = '';
            $this->length[$fd] = 0;
        }

        $this->buffer[$fd] .= $data;
        $buffer = &$this->buffer[$fd];

        do
        {
            if ($this->length[$fd] === 0)
            {
                $n = unpack('Nlen', substr($buffer, 0, 4));
                $this->length[$fd] = $n['len'];
                if ($n['len'] > self::MAX_PACKAGE_LEN)
                {
                    $this->serv->close($fd);
                    return;
                }
            }

            if (strlen($buffer) >= $this->length[$fd])
            {
                $this->onPackage($fd, substr($buffer, 0, $this->length[$fd]));
                $buffer = substr($buffer, $this->length[$fd]);
                $this->length[$fd] = 0;
            }
			else
			{
				break;
			}
        } while(strlen($buffer) > 0);
    }

    function onClose($serv, $fd)
    {
        unset($this->buffer[$fd], $this->length[$fd]);
    }

    function run($host, $port)
    {
        register_shutdown_function(array($this, 'errorHandler'));
        $this->serv = new swoole_server($host, $port);
		file_put_contents(PID_FILE_NAME, posix_getpid());
		
        $this->serv->set(array(
            'max_request' => 0,
// 			'dispatch_mode' => 3,
			'open_length_check' => true,
			'package_max_length' => 81920,
			'package_length_type' => 'n', //see php pack()
			'package_length_offset' => 0,
			'package_body_offset' => 2,
			'worker_num' => 2,
		));

        $this->serv->on('receive', array($this, 'onReceive'));
        $this->serv->on('close', array($this, 'onClose'));
        $this->serv->start();
    }

    function errorHandler()
    {
        if(!empty($this->current_fd))
        {
            $rsp = Proxy::shutdown_handler();
            $rsp && $this->serv->send($this->current_fd, $rsp);
        }
    }
}


