<?php
$serv = new swoole_server("127.0.0.1", 9500);
$serv->set(array(
    'worker_num' => 2,
    'task_worker_num' => 2, //database connection pool
    'task_worker_max'=>100
));
function my_onReceive($serv, $fd, $from_id, $data)
{
    $result = $serv->taskwait("show tables");
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
    if ($link == null) {
        $link  = new PDO('mysql:host=192.168.20.131;dbname=db1', "admin", "admin");;
        if (!$link) {
            $link = null;
            $serv->finish("ER:laksdjflksdjf");
            return;
        }   
    }   
    $result = $link->query($sql);
    if (!$result) {
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