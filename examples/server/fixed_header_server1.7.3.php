<?php
$serv = new SocketServer();
$serv->run('0.0.0.0', 9504);

class SocketServer
{
    protected $serv; //swoole server

    const MAX_PACKAGE_LEN = 8000000; //max data accept

    function run($host, $port)
    {
        register_shutdown_function(array($this, 'errorHandler'));
        $this->serv = new swoole_server($host, $port);

        $this->serv->set(array(
            //'daemonize' => true,
            'max_request' => 2000, //reload worker by run xx times
            'dispatch_mode' => 3, //who come first who is
            'worker_num' => 5, //how much worker will start
            'reactor_num' => 2, // depend cpu how much cpu you have
            'backlog' => 128, //accept queue
            'open_cpu_affinity' => 1, //get cpu more time
            'open_tcp_nodelay' => 1, // for small packet to open
            'tcp_defer_accept' => 5, //client will accept when not have data
            'max_conn' => 10000,
            'task_worker_num' => 10,
            'task_ipc_mode' => 2, //use queue with "who come first who is"
            'message_queue_key' => 0x72000100,
            'open_length_check' => true,
            'package_max_length' => 999999999,
            'package_length_type' => 'N', //see php pack()
            'package_length_offset' => 0,
            'package_body_offset' => 4,

        ));

        $this->serv->on('receive', array($this, 'onReceive'));
        $this->serv->on('close', array($this, 'onClose'));
        $this->serv->on('task', array($this, 'onTask'));
        $this->serv->on('finish', array($this, 'onFinish'));
        $this->serv->start();
    }


    function onReceive($serv, $fd, $from_id, $data)
    {
                $packet = json_decode(substr($data,4), true);

                //todo::包可能解析失败
                $packet["socketfd"] = $fd;
                $task_id = $serv->task(json_encode($packet));
		//todo::任务可能下发失败
    }

    function onTask($serv, $task_id, $from_id, $data)
    {
        $data = json_decode($data, true);
        $fd = $data["socketfd"];

        $result = array(
            "code" => "0",
            "msg" => "ok",
            "data" => $data,
        );
        $serv->send($fd, json_encode($result));
    }

    function onFinish($serv, $task_id, $data)
    {

    }

    function onClose($serv, $fd)
    {

    }

    function errorHandler()
    {
        //if (!empty($this->current_fd)) {
        //    $rsp = Proxy::shutdown_handler();
        //    $rsp && $this->serv->send($this->current_fd, $rsp);
        //}
    }
}
