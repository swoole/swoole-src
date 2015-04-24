<?php
$serv = new swoole_server("127.0.0.1", 9500);
$serv->set(array(
    'worker_num' => 1,
    'task_worker_num' => 8, //database connection pool
    'db_uri' => 'mysql:host=127.0.0.1;dbname=test',
    'db_user' => 'root',
    'db_passwd' => 'root',
//    'task_worker_max'=>100
));
function my_onReceive($serv, $fd, $from_id, $data)
{
    $result = $serv->taskwait($data);
    if ($result !== false) {
        list($status, $db_res) = explode(':', $result, 2); 
        if ($status == 'OK') {
            $serv->send($fd, var_export(unserialize($db_res), true) . "\n");
        } else {
            $serv->send($fd, $db_res);
        }   
        return;
    } else {
        $serv->send($fd, "Error. Task timeout\n");
    }   
}
function my_onTask($serv, $task_id, $from_id, $sql)
{
    static $link = null;
    if ($link == null)
    {
        $link = new PDO($serv->setting['db_uri'], $serv->setting['db_user'], $serv->setting['db_passwd']);;
        if (!$link)
        {
            $link = null;
            $serv->finish("ER: connect database failed.");
            return;
        }
    }
    $result = $link->query($sql);
    if (!$result)
    {
        $serv->finish("ER: query error");
        return;
    }
    $data = $result->fetchAll();
    $serv->finish("OK:" . serialize($data));
}
function my_onFinish($serv, $data)
{
    echo "AsyncTask Finish:Connect.PID=" . posix_getpid() . PHP_EOL;
}
$serv->on('Receive', 'my_onReceive');
$serv->on('Task', 'my_onTask');
$serv->on('Finish', 'my_onFinish');
$serv->start();