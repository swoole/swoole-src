<?php
if (empty($argv[1])) {
    die("php ip.php sin_addr\n");
}
$v = $argv[1];
$n = unpack('Nip', $v);
$ip = long2ip($n['ip']);
$results = `curl http://freeapi.ipip.net/$ip`;
echo "IP: $ip, LOCATION: $results\n";

