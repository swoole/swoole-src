<?php
echo "Sending text to msg queue.\n";

class SwooleTask
{
    protected $queueId;
    protected $workerId;

    function __construct($key, $workerId)
    {
        $this->queueId = msg_get_queue($key);
        if ($this->queueId === false)
        {
            throw new \Swoole\Exception("msg_get_queue() failed.");
        }
        $this->workerId = $workerId;
    }

    function dispatch($data)
    {
        if (!msg_send($this->queueId, $this->workerId + 1, Swoole\Server\Task::pack($data), false))
        {
            return false;
        }
        else
        {
            return true;
        }
    }
}

$task = new SwooleTask(0x70001001, 0);
//普通字符串
$task->dispatch("Hello from PHP!");
//数组
$task->dispatch(array('data' => str_repeat('A', 1024), 'type' => 1));
//大包
$task->dispatch(array('data' => str_repeat('B', 1024 * 32), 'type' => 2));
