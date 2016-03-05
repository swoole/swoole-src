<?php

$socket = stream_socket_server("tcp://0.0.0.0:8000", $errno, $errstr);
if (!$socket) {
  echo "$errstr ($errno)<br />\n";
} else {
  while ($conn = stream_socket_accept($socket)) {
	  $i = 0;
	  while(true) {
		    $r = fwrite($conn, str_repeat("A", 8192));
		    usleep(1000);
		    if (empty($r)) {
				echo "count $i \n";
				var_dump($r);
				stream_set_blocking($conn, 0);
			}
		    else{
				$i++;
			} 
			if ($r === false) break;
	  }
	  fclose($conn);
   
  }
  fclose($socket);
}
