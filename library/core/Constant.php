<?php

namespace Swoole;

class Constant
{
    const EVENT_RECEIVE = 'receive';
    const EVENT_CONNECT = 'connect';
    const EVENT_CLOSE = 'close';
    const EVENT_PACKET = 'packet';
    const EVENT_REQUEST = 'request';
    const EVENT_MESSAGE = 'message';
    const EVENT_OPEN = 'open';
    const EVENT_HANDSHAKE = 'handshake';
    const EVENT_TASK = 'task';
    const EVENT_FINISH = 'finish';
    const EVENT_START = 'start';
    const EVENT_SHUTDOWN = 'shutdown';
    const EVENT_WORKER_START = 'workerStart';
    const EVENT_WORKER_EXIT = 'workerExit';
    const EVENT_WORKER_ERROR = 'workerError';
    const EVENT_WORKER_STOP = 'workerStop';
    const EVENT_MANAGER_START = 'managerStart';
    const EVENT_MANAGER_STOP = 'managerStop';

    const OPTION_CHROOT = 'chroot';
    const OPTION_USER = 'user';
    const OPTION_GROUP = 'group';
}
