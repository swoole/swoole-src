define timer_list
    if SwooleTG.timer
        printf "current timer number: %d, round: %d\n", SwooleTG.timer.num,SwooleTG.timer->round
        set $running = 1
        set $i = 1
        while $running
            if $i < SwooleTG.timer->heap->num
                set $tmp = SwooleTG.timer->heap->nodes[$i]
                set $node = (swTimer_node *)$tmp->data
                if $node
                   printf "\t timer[%d] exec_msec:%ld round:%ld\n", $node->id, $node->exec_msec, $node->round
                end
            else
                set $running = 0
            end
            set $i = $i + 1
        end
    else
        printf "no timer\n"
    end
end

define reactor_info
    if SwooleTG.reactor
        printf "\t reactor id: %d\n",SwooleTG.reactor->id
        printf "\t running: %d\n", SwooleTG.reactor->running
        printf "\t event_num: %d\n", SwooleTG.reactor->event_num
        printf "\t aio_task_num: %d\n", SwooleTG.aio_task_num
        printf "\t max_event_num: %d\n", SwooleTG.reactor->max_event_num
        printf "\t check_timer: %d\n", SwooleTG.reactor->check_timer
        printf "\t timeout_msec: %d\n", SwooleTG.reactor->timeout_msec
    end
end

define sw_hash_map_list
    set $hmap = $arg0
    if $hmap
        if $hmap->root->hh.tbl->num_items == 0
            echo "no content\n"
        else
            set $running = 1
            set $it = $hmap->iterator
            if $it == 0
               set $it = $hmap->root
            end
            while $running
                
                set $tmp = (swHashMap_node *)$it->hh.next
                if $tmp
                    printf "key_int[%d] key_str:%s data:%p\n", $tmp->key_int, $tmp->key_str, $tmp->data
                    set $it = $tmp
                else
                    set $running = 0
                end
            end 
        end
    end
end

define co_list
    call swoole_coroutine_iterator_reset()
    set $running = 1
    while $running
        set $co = swoole_coroutine_iterator_each()
        if $co
            printf "coroutine %ld ", $co->cid
            if $co->state == 0
                printlnc $GREEN "SW_CORO_INIT"
            end
            if $co->state == 1
                printlnc $YELLOW "SW_CORO_WAITING"
            end
            if $co->state == 2
                printlnc $GREEN "SW_CORO_RUNNING"
            end
            if $co->state == 3
                printlnc $CYAN "SW_CORO_END"
            end
        else
            set $running = 0
        end
    end
end

define co_bt
    if swoole_coroutine_count() == 0
        printf "no coroutine is running\n"
    end
    ____sw_executor_globals
    if $argc > 0
        set $cid = (int) $arg0
    else
        if 'swoole::Coroutine::current'
            set $cid = (int) 'swoole::Coroutine::current'->cid
        else
            set $cid = -1
        end
    end

    printf "coroutine cid: [%d]\n", $cid
    if $argc > 0
        __co_bt $cid
    else
        sw_dump_bt php_swoole_get_executor_globals()->current_execute_data
    end
end
document co_bt
    dump current coroutine or the cid backtrace.
    useage: co_bt [cid]
end

define __co_bt
    set $cid = (int)$arg0
    set $co = swoole_coroutine_get($cid)
    if $co
        set $task = ('swoole::PHPContext' *) $co->get_task()
        if $task
            sw_dump_bt $task->execute_data
        end
    else
        printf "coroutines %d not found\n", $cid
    end
end

define co_status
    printf "\t c_stack_size: %d\n",  'swoole::Coroutine::stack_size'
    printf "\t active: %d\n",  'swoole::PHPCoroutine::active'
    printf "\t coro_num: %d\n",  swoole_coroutine_count()
    printf "\t peak_coro_num: %d\n",  'swoole::Coroutine::peak_num'
    printf "\t config: "
    print 'swoole::PHPCoroutine::config'
end

define ____sw_executor_globals
    set $eg = php_swoole_get_executor_globals()
end

define ____sw_print_str
    set $tmp = 0
    set $str = $arg0
    if $argc > 2
        set $maxlen = $arg2
    else
        set $maxlen = 256
    end

    printf "\""
    while $tmp < $arg1 && $tmp < $maxlen
        if $str[$tmp] > 31 && $str[$tmp] < 127
            printf "%c", $str[$tmp]
        else
            printf "\\%o", $str[$tmp]
        end
        set $tmp = $tmp + 1
    end
    if $tmp != $arg1
        printf "..."
    end
    printf "\""
end

define sw_dump_bt
    set $ex = $arg0
    while $ex
        printf "[%p] ", $ex
        set $func = $ex->func
        if $func
            if $ex->This->value.obj
                if $func->common.scope
                    printf "%s->", $func->common.scope->name->val
                else
                    printf "%s->", $ex->This->value.obj->ce.name->val
                end
            else
                if $func->common.scope
                    printf "%s::", $func->common.scope->name->val
                end
            end

            if $func->common.function_name
                printf "%s(", $func->common.function_name->val
            else
                printf "(main"
            end

            set $callFrameSize = (sizeof(zend_execute_data) + sizeof(zval) - 1) / sizeof(zval)

            set $count = $ex->This.u2.num_args
            set $arg = 0
            while $arg < $count
                if $arg > 0
                    printf ", "
                end
                set $zvalue = (zval *) $ex + $callFrameSize + $arg
                set $type = $zvalue->u1.v.type
                if $type == 1
                    printf "NULL"
                end
                if $type == 2
                    printf "false"
                end
                if $type == 3
                    printf "true"
                end
                if $type == 4
                    printf "%ld", $zvalue->value.lval
                end
                if $type == 5
                    printf "%f", $zvalue->value.dval
                end
                if $type == 6
                    ____sw_print_str $zvalue->value.str->val $zvalue->value.str->len
                end
                if $type == 7
                    printf "array(%d)[%p]", $zvalue->value.arr->nNumOfElements, $zvalue
                end
                if $type == 8
                    printf "object[%p]", $zvalue
                end
                if $type == 9
                    printf "resource(#%d)", $zvalue->value.lval
                end
                if $type == 10
                    printf "reference"
                end
                if $type > 10
                    printf "unknown type %d", $type
                end
                set $arg = $arg + 1
            end

            printf ") "
        else
            printf "??? "
        end
        if $func != 0
            if $func->type == 2
                printf "%s:%d ", $func->op_array.filename->val, $ex->opline->lineno
            else
                printf "[internal function]"
            end
        end
        set $ex = $ex->prev_execute_data
        printf "\n"
    end
end

# ======== color ========
set $BLACK   = 0
set $RED     = 1
set $GREEN   = 2
set $YELLOW  = 3
set $BLUE    = 4
set $MAGENTA = 5
set $CYAN    = 6
set $WHITE   = 7

define color
    if $argc == 0
        set $arg = 0
    else
        set $arg = $arg0 + 30
    end
    printf "%c[%dm", 27, $arg
end

# ======== print ========

define printlnc
    color $arg0
    printf "%s\n", $arg1
    color
end
