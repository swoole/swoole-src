#!/usr/local/bin/php
<?php
/**
 * usage: php upload_client.php -h 127.0.0.1 -p 9507 -f test.jpg
 */
$client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
$args = getopt("p:h:f:t");

if (empty($args['h']) or empty($args['f'])) 
{
    echo "Usage: php {$argv[0]} -h server_ip -p server_port -f file -t timeout\n";
    exit;
}

if (empty($args['p']))
{
	$args['p'] = 9507;
}

if (empty($args['t'])) 
{
    $args['t'] = 30;
}

$file = $args['f'];
$size = filesize($file);

if (!is_file($file)) {
    die("Error: file '{$args['f']}' not found\n");
}

if (!$client->connect($args['h'], $args['p'], $args['t'], 0)) {
    echo "Error: connect to server failed. " . swoole_strerror($client->errCode);
    die("\n");
}

$data = array(
    'name' => basename($file),
    'size' => $size,
);

if (!$client->send(json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\r\n\r\n")) {
    die("Error: send header failed.\n");
}
getResponse($client);

echo "Start transport. file={$file}, size={$size}\n";

$fp = fopen($file, 'r');
if (!$fp) {
    die("Error: open $file failed.\n");
}
$i = 0;
while(!feof($fp))
{
    $read = fread($fp, 8000);
    if (!$client->send($read)) {
        echo "send failed. ErrCode=".$client->errCode."\n";
        break;
    }
}
getResponse($client);
echo "Success. send_size = $size\n";

function getResponse(swoole_client $client)
{
    $recv = $client->recv();
    if (!$recv) {
        die("Error: recv header failed.\n");
    }
    $respCode = json_decode($recv, true);
    if (!$respCode) {
        die("Error: header json_decode failed.\n");
    }
    if ($respCode['code'] != 0) {
        die("Server: message={$respCode['msg']}.\n");
    } else
    echo "[FromServer]\t{$respCode['msg']}\n";
    return true;
}
