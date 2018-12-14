<?php
$socket = stream_socket_server("tcp://0.0.0.0:9501", $errno, $errstr);
if (!$socket) {
    echo "$errstr ($errno)<br />\n";
} else {
    while (true) {
        $conn = stream_socket_accept($socket);
        if (!$conn) {
            continue;
        }
        $i = 0;
        $length = 0;
        while(true) {
            $data = fread($conn, 8192);
            if ($data == false)
            {
                break;
            }
            $length += strlen($data);
            echo "recv " . $length . " bytes\n";
            usleep(100000);
        }
        fclose($conn);
        echo "closed\n";
    }
    fclose($socket);
}
