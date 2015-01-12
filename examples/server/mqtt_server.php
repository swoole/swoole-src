<?php
function decodeValue($data)
{
    return 256 * ord($data[0]) + ord($data[1]);
}

function decodeString($data)
{
    $length = decodeValue($data);
    return substr($data, 2, $length);
}

function mqtt_get_header($data)
{
    $byte = ord($data[0]);

    $header['type'] = ($byte & 0xF0) >> 4;
    $header['dup'] = ($byte & 0x08) >> 3;
    $header['qos'] = ($byte & 0x06) >> 1;
    $header['retain'] = $byte & 0x01;

    return $header;
}

function event_connect($header, $data)
{
    $connect_info['protocol_name'] = decodeString($data);
    $offset = strlen($connect_info['protocol_name']) + 2;

    $connect_info['version'] = ord(substr($data, $offset, 1));
    $offset += 1;

    $byte = ord($data[$offset]);
    $connect_info['willRetain'] = ($byte & 0x20 == 0x20);
    $connect_info['willQos'] = ($byte & 0x18 >> 3);
    $connect_info['willFlag'] = ($byte & 0x04 == 0x04);
    $connect_info['cleanStart'] = ($byte & 0x02 == 0x02);
    $offset += 1;

    $connect_info['keepalive'] = decodeValue(substr($data, $offset, 2));
    $offset += 2;
    $connect_info['clientId'] = decodeString(substr($data, $offset));
    return $connect_info;
}


$serv = new swoole_server("127.0.0.1", 9501, SWOOLE_BASE);

$serv->set(
    array(
        'open_mqtt_protocol' => 1,
        'worker_num' => 1,
    )
);

$serv->on('connect', function ($serv, $fd){
	echo "Client:Connect.\n";
});

$serv->on('receive', function ($serv, $fd, $from_id, $data) {

        $header = mqtt_get_header($data);
        var_dump($header);

        if ($header['type'] == 1)
        {
            $resp = ord(32) . ord(2) . ord(0) . ord(0);
            event_connect($header, substr($data, 2));
            $serv->send($fd, $resp);
        }
        elseif ($header['type'] == 3)
        {
            $offset = 2;
            $topic = decodeString(substr($data, $offset));
            $offset += strlen($topic) + 2;
            $msg = substr($data, $offset);
            echo "client msg: $topic\n---------------------------------\n$msg\n";

            //file_put_contents(__DIR__.'/data.log', $data);
        }
	    echo "received length=".strlen($data)."\n";
});

$serv->on('close', function ($serv, $fd) {
	echo "Client: Close.\n";
});

$serv->start();

