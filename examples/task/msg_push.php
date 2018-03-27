<?php


echo "Sending text to msg queue.\n";

class SwooleTask
{
    protected $queueId;
    protected $workerId;
    protected $taskId = 0;

    function __construct($key, $workerId = 0)
    {
        $this->queueId = msg_get_queue($key);
        if ($this->queueId === false)
        {
            throw new \Swoole\Exception("msg_get_queue() failed.");
        }
        $this->workerId = $workerId;
    }

    protected function pack($data)
    {
        $fromFd = 0;
        $type = 7;
        if (!is_string($data))
        {
            $data = serialize($data);
            $fromFd |= 2;
        }
        if (strlen($data) >= 8180)
        {
            $tmpFile = tempnam('/tmp/', 'swoole.task');
            file_put_contents($tmpFile, $data);
            $data = pack('l', strlen($data)) . $tmpFile . "\0";
            $fromFd |= 1;
            $len = 128 + 24;
        }
        else
        {
            $len = strlen($data);
        }
        //typedef struct _swDataHead
        //{
        //    int fd;
        //    uint16_t len;
        //    int16_t from_id;
        //    uint8_t type;
        //    uint8_t flags;
        //    uint16_t from_fd;
        //} swDataHead;
        return pack('lSsCCS', $this->taskId++, $len, $this->workerId, $type, 0, $fromFd) . $data;
    }

    function dispatch($data)
    {
        if (!msg_send($this->queueId, $this->workerId + 1, $this->pack($data), false))
        {
            return false;
        }
        else
        {
            return true;
        }
    }
}

$task = new SwooleTask(0x70001001);
//普通字符串
$task->dispatch("Hello from PHP!");
//数组
$task->dispatch(array('data' => str_repeat('A', 1024), 'type' => 1));
//大包
$task->dispatch(array('data' => str_repeat('B', 1024 * 32), 'type' => 2));