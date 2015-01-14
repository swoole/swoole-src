<?php

class DebugServer
{
    protected $alloc_point = array();
    protected $free_point = array();
    protected $index = 0;

    function package_decode($pkg)
    {
        list($tag, $_vars) = explode(':', $pkg, 2);
        $tag = trim($tag);
        $vars = explode(',', trim($_vars));
        $data = array();
        foreach($vars as $str)
        {
            list($k, $v) = explode('=', trim($str));
            $data[$k] = $v;
        }

        if ($tag == 'alloc')
        {
            if (isset( $this->alloc_point[$data['ptr']]))
            {
                echo "ptr={$data['ptr']} is alloced.";
            }
            else
            {
                $this->alloc_point[$data['ptr']] = $this->index ++;
            }
        }
        elseif ($tag == 'free')
        {
            $this->free_point[$data['ptr']] = $this->index ++;
        }
        elseif($tag == 'invalid')
        {
            foreach($this->alloc_point as $k => $v)
            {
                echo "$k => $v\n";
            }
        }
        else
        {
            var_dump($tag, $data);
        }
    }

    function run()
    {
        $socket = stream_socket_server("udp://127.0.0.1:9999", $errno, $errstr, STREAM_SERVER_BIND);
        if (!$socket)
        {
            die("$errstr ($errno)");
        }
        while(1)
        {
            $pkt = stream_socket_recvfrom($socket, 65535, 0, $peer);
            $this->package_decode($pkt);
            //echo "$peer: $pkt\n";
            //stream_socket_sendto($socket, date("D M j H:i:s Y\r\n"), 0, $peer);
        }
    }
}

$svr = new DebugServer;
$svr->run();