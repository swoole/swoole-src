<?php
const SIZE = 240000;
const SEND_COUNT = 10000;
const WORKER_COUNT = 4;
const PORT = 9903;
const PAGE_SIZE = 4096;
const MAGIC_STR_SIZE = 32;
const PRINT_N = 100;
const DEBUG = true;

$sockets = stream_socket_pair(AF_UNIX, SOCK_DGRAM, 0);
if (!$sockets) {
    die(
    "error\n"
    );
}

stream_set_chunk_size($sockets[0], SIZE + PAGE_SIZE * 2);
stream_set_chunk_size($sockets[1], SIZE + PAGE_SIZE * 2);

function validatePacket($data)
{
    $header = substr($data, 0, MAGIC_STR_SIZE);
    $size = strlen($data);
    for ($i = MAGIC_STR_SIZE; $i < $size - PAGE_SIZE; $i += PAGE_SIZE) {
        $_n = unpack('Npos', substr($data, $i, 4));
        $str = substr($data, $i + $_n['pos'], MAGIC_STR_SIZE);
        if ($str !== $header) {
            echo "PkgLen=" . strlen($data) . ", index={$i}, Pos={$_n['pos']}, ";
            var_dump($str, "-------------------------------------\n");
            return false;
        }
    }
    return true;
}

function printLog($str)
{
    if (DEBUG) {
        echo $str . "\n";
    }
}

$pool = new Swoole\Process\Pool(WORKER_COUNT + 1);

$pool->on(\Swoole\Constant::EVENT_WORKER_START, function ($p, $i) use ($sockets) {
    printLog("Worker-{$i} is started");
    if ($i == 0) {
        $j = 0;
        while (true) {
            $pkt = stream_socket_recvfrom($sockets[0], SIZE + PAGE_SIZE);
            if ($j % PRINT_N == 0) {
                printLog("[$j]\tRecv Packet, Len=" . strlen($pkt));
            }
            if (!validatePacket($pkt)) {
                echo "$j ERROR\n";
            }
            $j++;
        }
    } else {
        for ($j = 0; $j < SEND_COUNT; $j++) {
            $header = _string(base64_encode(random_bytes(MAGIC_STR_SIZE)))->substr(0, 32)->toString();
            $data = $header;
            $size = rand(SIZE / 2, SIZE);
            while (strlen($data) < $size) {
                $n = mt_rand(4, 4096 - MAGIC_STR_SIZE);
                $page = pack('N', $n);
                if ($n - 4 > 0) {
                    $page .= str_repeat(' ', $n - 4);
                }
                $page .= $header;
                $page .= str_repeat(' ', PAGE_SIZE - $n - MAGIC_STR_SIZE);
                $data .= $page;
            }
            if ($j % PRINT_N == 0) {
                printLog("[$j]\tSend Packet, Len=" . strlen($data));
            }
            fwrite($sockets[1], $data);
        }
    }
    printLog("Worker-{$i} is stopped");
    sleep(100);
});

$pool->start();