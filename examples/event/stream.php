<?php
$fp = stream_socket_client("tcp://127.0.0.1:9502", $errno, $errstr, 30);
if (!$fp) {
    exit("$errstr ($errno)<br />\n");
}
fwrite($fp, "HELLO world");

function stream_onRead($fp)
{
	echo fread($fp, 1024)."\n";
	sleep(1);
	Swoole\Event::write($fp, "hello world");
	//Swoole\Event::set($fp, null, null, SWOOLE_EVENT_READ | SWOOLE_EVENT_WRITE);
	//Swoole\Event::del($fp);
    //fclose($fp);
}


Swoole\Event::add($fp, 'stream_onRead');

echo "start\n";
