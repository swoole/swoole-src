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
	swoole_event_set($fp, null, null, SWOOLE_EVENT_READ | SWOOLE_EVENT_WRITE);
	//swoole_event_del($fp);
    //fclose($fp);
}

function stream_onWrite($fp)
{
	fwrite($fp, "hi swoole\n");
	swoole_event_set($fp, null, null, SWOOLE_EVENT_READ);
}

swoole_event_add($fp, 'stream_onRead', 'stream_onWrite');

echo "start\n";
