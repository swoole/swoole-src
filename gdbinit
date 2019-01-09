define timer_list
    if SwooleG.timer.initialized == 1
        printf "current timer number: %d, round: %d\n", SwooleG.timer.num,SwooleG.timer->round
        set $running = 1
        set $i = 1
        while $running
            if $i < SwooleG.timer->heap->num
                set $tmp = SwooleG.timer->heap->nodes[$i]
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
    if SwooleG.main_reactor
        printf "current reactor id: %d\n",SwooleG.main_reactor->id
        printf "\t running: %d\n", SwooleG.main_reactor->running
        printf "\t event_num: %d\n", SwooleG.main_reactor->event_num
        printf "\t max_event_num: %d\n", SwooleG.main_reactor->max_event_num
        printf "\t check_timer: %d\n", SwooleG.main_reactor->check_timer
        printf "\t timeout_msec: %d\n", SwooleG.main_reactor->timeout_msec
    end
end

define co_list
    call swoole_coro_iterator_reset()
    set $running = 1
    while $running
        set $co = swoole_coro_iterator_each()
        
        if $co
            printf "coroutine %d ", $co->get_cid()
            if $co->state == 0
                printf "%s\n", "SW_CORO_INIT"
            end
            if $co->state == 1
                color $RED
                printf "%s\n", "SW_CORO_WAITING"
                color_reset
            end      
            if $co->state == 2
                color $GREEN
                printf "%s\n", "SW_CORO_RUNNING"
                color_reset
            end
            if $co->state == 3
                printf "%s\n", "SW_CORO_END"
            end
        else
            set $running = 0
        end
    end
    
end

define co_bt
    if swoole_coro_count() == 0
        printf "no coroutines running\n"
    end
    ____executor_globals
    if $argc > 0
        set $cid = (int)$arg0
    else
        set $cid = 'swoole::Coroutine::get_current_cid'()
    end
    
    printf "coroutine cid:[%d]\n",$cid
    __co_bt $cid
end

document co_bt
    dump current coroutine or the cid backtrace.
    useage: co_bt [cid]
end

define __co_bt
    set $cid = (int)$arg0
    set $co = swoole_coro_get($cid)
    if $co
        set $task = (php_coro_task *)$co->task
        if $task
            dump_bt $eg.current_execute_data
        end
    else
        printf "coroutines %d not found\n", $cid
    end
end

define co_status
    printf "\t c_stack_size: %d\n",  'swoole::Coroutine::stack_size'
    printf "\t call_stack_size: %d\n",  'swoole::Coroutine::call_stack_size'
    printf "\t active: %d\n",  'swoole::PHPCoroutine::active'
    printf "\t coro_num: %d\n",  swoole_coro_count()
    printf "\t max_coro_num: %d\n",  'swoole::PHPCoroutine::max_num'
    printf "\t peak_coro_num: %d\n",  'swoole::Coroutine::peak_num'
end

define ____executor_globals
    if basic_functions_module.zts
        if !$tsrm_ls
            set $tsrm_ls = ts_resource_ex(0, 0)
        end
        set $eg = ((zend_executor_globals*) (*((void ***) $tsrm_ls))[executor_globals_id-1])
    else
        set $eg = executor_globals
    end
end

define ____print_str
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

define dump_bt
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
                    ____print_str $zvalue->value.str->val $zvalue->value.str->len
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

# __________________color functions_________________
#
set $USECOLOR = 1
# color codes
set $BLACK = 0
set $RED = 1
set $GREEN = 2
set $YELLOW = 3
set $BLUE = 4
set $MAGENTA = 5
set $CYAN = 6
set $WHITE = 7

set $COLOR_REGNAME = $GREEN
set $COLOR_REGVAL = $BLACK
set $COLOR_REGVAL_MODIFIED  = $RED
set $COLOR_SEPARATOR = $BLUE
set $COLOR_CPUFLAGS = $RED

# this is ugly but there's no else if available :-(
define color
 if $USECOLOR == 1
    # BLACK
    if $arg0 == 0
        echo \033[30m
    else
        # RED
        if $arg0 == 1
            echo \033[31m
        else
            # GREEN
            if $arg0 == 2
                echo \033[32m
            else
                # YELLOW
                if $arg0 == 3
                    echo \033[33m
                else
                    # BLUE
                    if $arg0 == 4
                        echo \033[34m
                    else
                        # MAGENTA
                        if $arg0 == 5
                            echo \033[35m
                        else
                            # CYAN
                            if $arg0 == 6
                                echo \033[36m
                            else
                                # WHITE
                                if $arg0 == 7
                                    echo \033[37m
                                end
                            end
                        end
                    end
                end
            end
        end
     end
 end
end

define color_reset
    if $USECOLOR == 1
       echo \033[0m
    end
end

define color_bold
    if $USECOLOR == 1
       echo \033[1m
    end
end

define color_underline
    if $USECOLOR == 1
       echo \033[4m
    end
end
