define ____get_current
    if swCoroG.call_stack_size > 0
        set $current_co = (coroutine_t*)swCoroG.call_stack[swCoroG.call_stack_size - 1]
        set $current_cid = $current_co->cid
        set $current_task = (coro_task *)$current_co->task
    else
        set $current_co = null
        set $current_cid = -1
        set $current_task = null
    end
end

define co_list
    if COROG.coro_num == 0
        printf "no coroutines running \n"
    end
    ____executor_globals
    set $cid = 1
    while $cid < COROG.coro_num + 1
        if swCoroG.coroutines[$cid]
            printf "coroutine %d ", $cid
            set $co = swCoroG.coroutines[$cid]
            if $co->state == 0
                printf "%s\n", "SW_CORO_INIT"
            end
            if $co->state == 1
                color $RED
                printf "%s\n", "SW_CORO_YIELD"
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
        end
        set $cid = $cid + 1
    end
end

define co_backtrace
    if COROG.coro_num == 0
        printf "no coroutines running \n"
    end
    ____executor_globals
    ____get_current    
    if $current_co && $current_co->cid
        color $GREEN
        printf "coroutine cid:[%d]\n",$current_co->cid
        color_reset
        co_bt $current_co->cid
    else   
        printf "no coroutine running\n"
    end
end

document co_backtrace
    dump current coroutine backtrace.
end

define co_bt
    set $cid = (int)$arg0
    if swCoroG.coroutines[$cid]     
        if $current_co && $cid == $current_co->cid
            dump_bt $eg.current_execute_data 
        else   
            set $co = (coroutine_t *)swCoroG.coroutines[$cid]
            set $task = (coro_task *)$co->task
            if $task
                set $backup = $eg.current_execute_data
                dump_bt $task->yield_execute_data
                set $eg.current_execute_data = $backup
            end
        end
    else
        printf "coroutines %d is not running\n", $cid
    end
end

define co_status
    printf "Coro stack_size: %d\n",  swCoroG.stack_size
    printf "Coro call_stack_size: %d\n",  swCoroG.call_stack_size
    printf "Coro active: %d\n",  COROG.active
    printf "Coro coro_num: %d\n",  COROG.coro_num
    printf "Coro max_coro_num: %d\n",  COROG.max_coro_num
    printf "Coro peak_coro_num: %d\n",  COROG.peak_coro_num
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