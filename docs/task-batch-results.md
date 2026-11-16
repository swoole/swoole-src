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
