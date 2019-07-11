<?php
$serv = new SocketServer();
$serv->run('0.0.0.0', 9504);

class SocketServer
{
    protected $serv; //swoole server

    const MAX_PACKAGE_LEN = 8000000; //max data accept

    function run($host, $port)
    {
        $this->serv = new swoole_server($host, $port);

        $this->serv->set(array(
            'enable_coroutine' => false,
//            'dispatch_mode' => 3, //who come first who is
            'worker_num' => 1, //how much worker will start
            'open_length_check' => true,
            'package_max_length' => 8 * 1024 * 1024,
            'package_length_type' => 'N', //see php pack()
            'package_length_offset' => 0,
            'package_body_offset' => 4,
        ));

        $this->serv->on('receive', array($this, 'onReceive'));
        $this->serv->start();
    }

    function onReceive($serv, $fd, $tid, $data)
    {
        echo "recv " . strlen($data) . " bytes\n";
        $packet = substr($data, 4);
        $result = array(
            "code" => "0",
            "msg" => "ok",
            "data" => $packet,
        );
        $resp = json_encode($result);
        $send_data = pack('N', strlen($resp)) . $resp;
        echo "send " . strlen($send_data) . " bytes\n";
        $serv->send($fd, $send_data);
    }
}
