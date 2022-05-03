# Linux 信号列表

## 完整对照表

| 信号      | 取值     | 默认动作 | 含义（发出信号的原因）                  |
| --------- | -------- | -------- | --------------------------------------- |
| SIGHUP    | 1        | Term     | 终端的挂断或进程死亡                    |
| SIGINT    | 2        | Term     | 来自键盘的中断信号                      |
| SIGQUIT   | 3        | Core     | 来自键盘的离开信号                      |
| SIGILL    | 4        | Core     | 非法指令                                |
| SIGABRT   | 6        | Core     | 来自 abort 的异常信号                   |
| SIGFPE    | 8        | Core     | 浮点例外                                |
| SIGKILL   | 9        | Term     | 杀死                                    |
| SIGSEGV   | 11       | Core     | 段非法错误(内存引用无效)                |
| SIGPIPE   | 13       | Term     | 管道损坏：向一个没有读进程的管道写数据  |
| SIGALRM   | 14       | Term     | 来自 alarm 的计时器到时信号             |
| SIGTERM   | 15       | Term     | 终止                                    |
| SIGUSR1   | 30,10,16 | Term     | 用户自定义信号 1                        |
| SIGUSR2   | 31,12,17 | Term     | 用户自定义信号 2                        |
| SIGCHLD   | 20,17,18 | Ign      | 子进程停止或终止                        |
| SIGCONT   | 19,18,25 | Cont     | 如果停止，继续执行                      |
| SIGSTOP   | 17,19,23 | Stop     | 非来自终端的停止信号                    |
| SIGTSTP   | 18,20,24 | Stop     | 来自终端的停止信号                      |
| SIGTTIN   | 21,21,26 | Stop     | 后台进程读终端                          |
| SIGTTOU   | 22,22,27 | Stop     | 后台进程写终端                          |
|           |          |          |                                         |
| SIGBUS    | 10,7,10  | Core     | 总线错误（内存访问错误）                |
| SIGPOLL   |          | Term     | Pollable 事件发生(Sys V)，与 SIGIO 同义 |
| SIGPROF   | 27,27,29 | Term     | 统计分布图用计时器到时                  |
| SIGSYS    | 12,-,12  | Core     | 非法系统调用(SVr4)                      |
| SIGTRAP   | 5        | Core     | 跟踪/断点自陷                           |
| SIGURG    | 16,23,21 | Ign      | socket 紧急信号(4.2BSD)                 |
| SIGVTALRM | 26,26,28 | Term     | 虚拟计时器到时(4.2BSD)                  |
| SIGXCPU   | 24,24,30 | Core     | 超过 CPU 时限(4.2BSD)                   |
| SIGXFSZ   | 25,25,31 | Core     | 超过文件长度限制(4.2BSD)                |
|           |          |          |                                         |
| SIGIOT    | 6        | Core     | IOT 自陷，与 SIGABRT 同义               |
| SIGEMT    | 7,-,7    |          | Term                                    |
| SIGSTKFLT | -,16,-   | Term     | 协处理器堆栈错误(不使用)                |
| SIGIO     | 23,29,22 | Term     | 描述符上可以进行 I/O 操作               |
| SIGCLD    | -,-,18   | Ign      | 与 SIGCHLD 同义                         |
| SIGPWR    | 29,30,19 | Term     | 电力故障(System V)                      |
| SIGINFO   | 29,-,-   |          | 与 SIGPWR 同义                          |
| SIGLOST   | -,-,-    | Term     | 文件锁丢失                              |
| SIGWINCH  | 28,28,20 | Ign      | 窗口大小改变(4.3BSD, Sun)               |
| SIGUNUSED | -,31,-   | Term     | 未使用信号(will be SIGSYS)              |

## 非可靠信号

| 名称      | 说明                        |
| --------- | --------------------------- |
| SIGHUP    | 连接断开                    |
| SIGINT    | 终端中断符                  |
| SIGQUIT   | 终端退出符                  |
| SIGILL    | 非法硬件指令                |
| SIGTRAP   | 硬件故障                    |
| SIGABRT   | 异常终止(abort)             |
| SIGBUS    | 硬件故障                    |
| SIGFPE    | 算术异常                    |
| SIGKILL   | 终止                        |
| SIGUSR1   | 用户定义信号                |
| SIGUSR2   | 用户定义信号                |
| SIGSEGV   | 无效内存引用                |
| SIGPIPE   | 写至无读进程的管道          |
| SIGALRM   | 定时器超时(alarm)           |
| SIGTERM   | 终止                        |
| SIGCHLD   | 子进程状态改变              |
| SIGCONT   | 使暂停进程继续              |
| SIGSTOP   | 停止                        |
| SIGTSTP   | 终端停止符                  |
| SIGTTIN   | 后台读控制 tty              |
| SIGTTOU   | 后台写向控制 tty            |
| SIGURG    | 紧急情况(套接字)            |
| SIGXCPU   | 超过 CPU 限制(setrlimit)    |
| SIGXFSZ   | 超过文件长度限制(setrlimit) |
| SIGVTALRM | 虚拟时间闹钟(setitimer)     |
| SIGPROF   | 梗概时间超时(setitimer)     |
| SIGWINCH  | 终端窗口大小改变            |
| SIGIO     | 异步 I/O                    |
| SIGPWR    | 电源失效/重启动             |
| SIGSYS    | 无效系统调用                |

## 可靠信号

| 名称        | 用户自定义 |
| ----------- | ---------- |
| SIGRTMIN    |            |
| SIGRTMIN+1  |            |
| SIGRTMIN+2  |            |
| SIGRTMIN+3  |            |
| SIGRTMIN+4  |            |
| SIGRTMIN+5  |            |
| SIGRTMIN+6  |            |
| SIGRTMIN+7  |            |
| SIGRTMIN+8  |            |
| SIGRTMIN+9  |            |
| SIGRTMIN+10 |            |
| SIGRTMIN+11 |            |
| SIGRTMIN+12 |            |
| SIGRTMIN+13 |            |
| SIGRTMIN+14 |            |
| SIGRTMIN+15 |            |
| SIGRTMAX-14 |            |
| SIGRTMAX-13 |            |
| SIGRTMAX-12 |            |
| SIGRTMAX-11 |            |
| SIGRTMAX-10 |            |
| SIGRTMAX-9  |            |
| SIGRTMAX-8  |            |
| SIGRTMAX-7  |            |
| SIGRTMAX-6  |            |
| SIGRTMAX-5  |            |
| SIGRTMAX-4  |            |
| SIGRTMAX-3  |            |
| SIGRTMAX-2  |            |
| SIGRTMAX-1  |            |
| SIGRTMAX    |            |
