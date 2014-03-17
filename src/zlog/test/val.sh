unset ZLOG_PROFILE_ERROR
unset ZLOG_PROFILE_DEBUG_LOG 

rm -f press*log

valgrind --tool=callgrind ./test_press_zlog 1 10 10000
