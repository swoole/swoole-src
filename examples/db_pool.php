<?php
$serv = new swoole_http_server("127.0.0.1", 9500);

$serv->set(array(
    'worker_num' => 100,
    'task_worker_num' => 20, //database connection pool
    'db_uri' => 'mysql:host=127.0.0.1;dbname=test',
    'db_user' => 'root',
    'db_passwd' => 'root',
));

function my_onRequest_sync($req, $resp)
{
    global $serv;
    $result = $serv->taskwait("show tables");
    if ($result !== false)
    {
        $resp->end(var_export($result['data'], true));
        return;
    }
    else
    {
        $resp->status(500);
        $resp->end("Server Error, Timeout\n");
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
            return array("data" => '', 'error' => "connect database failed.");
        }
    }
    $result = $link->query($sql);
    if (!$result)
    {
        return array("data" => '', 'error' => "query error");
    }
    $data = $result->fetchAll();
    return array("data" => $data);
}

function my_onFinish($serv, $data)
{
    echo "AsyncTask Finish:Connect.PID=" . posix_getpid() . PHP_EOL;
}

$serv->on('Request', 'my_onRequest_sync');
$serv->on('Task', 'my_onTask');
$serv->on('Finish', 'my_onFinish');

$serv->start();
