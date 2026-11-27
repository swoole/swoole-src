# Server commands

`Swoole\Server::addCommand()` registers a PHP command handler, and `command()`
invokes a registered command from a coroutine. The target identifies where the
handler must execute. These APIs are separate from connection events and worker
reload/shutdown operations.

## THREAD mode limits

On `master`, THREAD mode supports commands only from the master thread to the
`SWOOLE_SERVER_COMMAND_MASTER` target. The handler and its reply callback execute
locally on that thread. PHP `addCommand()` accepts only that target in THREAD
mode; register the handler in the main thread before starting the server.

When the server bootstrap script is also executed by worker threads, guard the
registration accordingly:

```php
if (Swoole\Thread::getInfo()['is_main_thread']) {
    $server->addCommand('echo', SWOOLE_SERVER_COMMAND_MASTER,
        function ($server, string $message): string {
            return $message;
        });
}
```

Commands initiated by other threads return `false` with
`SWOOLE_ERROR_SERVER_UNRELATED_THREAD`. Commands from the master thread to
MANAGER, EVENT_WORKER, TASK_WORKER or REACTOR_THREAD return `false` with
`SWOOLE_ERROR_OPERATION_NOT_SUPPORT`. These checks happen before allocating a
pending command request. The same restrictions apply to native C++
`Server::command()` calls. PHP registration for unsupported targets, including
target masks combining MASTER with another target, also fails with
`SWOOLE_ERROR_OPERATION_NOT_SUPPORT` and a warning.

Cross-thread command dispatch and reply routing are not implemented. PHP command
handlers also require a registry in each target thread's VM before they can be
supported. A Callable registered in one VM cannot be executed directly by
another thread, and a reply cannot resume a coroutine on another thread.

These restrictions do not change PROCESS or BASE command behavior. THREAD
worker messaging and reload/shutdown APIs remain separate facilities.

## Waiting, cancellation and shutdown

`command()` is an administration API. It keeps its existing five-parameter
signature and waits indefinitely for a reply; it has no implicit deadline.
A target exiting or a lost reply does not automatically fail or retry a command.

`Coroutine::cancel()` and normal shutdown of the caller's server/BASE worker
return `false` with `SWOOLE_ERROR_CO_CANCELED`. New commands are rejected once
the caller is stopping. A forced terminal exit still takes precedence over
resuming PHP code.

Cancellation removes the reply registration before the PHP call returns.
A late response is discarded without accessing its former coroutine. Canceling
the wait does not stop or roll back the target handler: it may already have
performed side effects, so commands are never automatically retried.

Native C++ callers keep the existing success callback signature and overload.
They may use the extended overload to obtain a request ID, abandon its reply
with `cancel_command(id)`, and supply an error callback for owner shutdown.
Registration, reply handling and cancellation must all run on the command
caller's owner thread/process.
