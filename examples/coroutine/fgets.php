<?Php
$fp = fopen(__DIR__ . "/defer_client.php", "r");
stream_set_chunk_size($fp, 1024);

go(function () use ($fp)
{
    for($i = 0; $i<100;$i++) {
        $r =  co::fgets($fp);
        if (empty($r) and feof($fp))
        {
            //echo "EOF\n";
            break;
        }
        //echo "len=".strlen($r)."\n";
        echo $r;
        //echo "---------------------------------------\n";
        //var_dump($r);
        //co::sleep(1);
    }
});
