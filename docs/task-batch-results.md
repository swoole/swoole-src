# Task batch results in Swoole 6.3

Swoole 6.3 requires PHP 8.2 or later.

`Server::taskCo()` and `Server::taskWaitMulti()` share the same implementation
and result contract in Swoole 6.3. Both wait cooperatively inside a coroutine
and block outside a coroutine. The same worker-process restrictions apply.

Both methods preserve the original task keys and their iteration order.
Completion order does not determine the order of returned entries. This applies
to string keys, sparse integer keys, mixed arrays and ordinary lists. The input
array is not reindexed or modified.

```php
$tasks = ['users' => 'load-users', 7 => 'load-settings', 'posts' => 'load-posts'];
$results = $server->taskCo($tasks);

// Returned entries use the same keys and order: 'users', 7, 'posts'.
```

After at least one successful dispatch, the result contains every input key.
A failed dispatch, failed result decoding or unfinished task is represented by
`false`. A timeout sets `SWOOLE_ERROR_TASK_TIMEOUT`, including partial timeouts;
when every dispatched task times out, an array of `false` entries is returned.
Late results do not change a returned batch or enter a later batch.

An empty batch, a batch with no successful dispatch, or a batch setup/result-file
read failure returns `false` for the whole call. Empty batches and batches with
no successful dispatch set `SWOOLE_ERROR_TASK_DISPATCH_FAIL`.

These are intentional compatibility changes in 6.3. Applications that map
results back to keys by numeric position should pass an explicit list:

```php
$results = $server->taskWaitMulti(array_values($tasks));
```

Code that previously checked only for a whole-call `false` after a timeout must
also inspect the returned entries and `swoole_last_error()`.

Swoole 6.1 and 6.2 retain their existing waiting and timeout conventions and
positional numeric results. Their crash fix accepts associative/sparse input
without rejecting it. The established synchronous numeric-index behavior of
arrays already containing every index from zero to count minus one is retained,
including arrays inserted in a different order.

## Asynchronous worker replacement in PROCESS mode

With `reload_async` enabled, coroutine `taskwait()`, `taskCo()` and
`taskWaitMulti()` keep their results in the event worker that submitted them.
When its replacement receives a result belonging to that older process, it
forwards the result through a separate Unix datagram channel. The original
worker collects the result and resumes the original request coroutine.

Per-task callbacks passed to `Server::task()` also keep their originating worker
alive until their results are delivered. They run in that original process and
can submit further tasks while it drains. Only removal of an existing coroutine
waiter or per-task callback decrements the worker's waiting count, so duplicate
and late results cannot decrement it twice.

Tasks handled only by the global `onFinish` event do not keep the old worker
alive. Their results can be handled by its replacement; they do not require a
per-task callback context from the original process.

The draining worker stops reading its ordinary worker pipe, so this mechanism
cannot deliver new client requests to it. Existing request coroutines can still
submit further tasks while draining. Task completion, timeout and cancellation
update the worker's outstanding-wait count; an idle result receiver does not
prevent the worker from exiting.

Cached forwarding sockets are released automatically after twice
`max_wait_time`, measured from connection creation; subsequent replies do not
extend that deadline. Their cleanup timers are cancelled when the forwarding
worker starts draining, so an idle cache does not delay that worker's exit.
Sending failures and worker cleanup also release the socket and cancel its timer.
A forwarding worker that is itself replaced continues flushing queued replies
before exiting, subject to its own original `max_wait_time` deadline. Queued
forwards are an explicit exit condition, independent of its own task waiters.

The original `max_wait_time` deadline still applies. A task timeout, worker crash,
forced termination or forwarding error can leave unfinished results; this is not
a durable task-delivery guarantee. Large-result temporary files are unpacked by
the receiving owner, or cleaned up when a result can no longer be delivered.

This forwarding path covers asynchronous event-worker replacement in
`SWOOLE_PROCESS`. It does not provide the missing result-delivery path for
whole-server shutdown, where no replacement event worker reads the ordinary
pipe. BASE/THREAD modes and blocking task waits retain their existing paths.
