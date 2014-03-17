exe = 		\
	test_tmp	\
	test_longlog	\
	test_buf	\
	test_bitmap	\
	test_conf	\
	test_hashtable	\
	test_hello	\
	test_hex	\
	test_init	\
	test_level	\
	test_leak	\
	test_mdc	\
	test_record	\
	test_pipe	\
	test_press_zlog		\
	test_press_zlog2	\
	test_press_write	\
	test_press_write2	\
	test_press_syslog	\
	test_syslog	\
	test_default \
	test_profile

all     :       $(exe)

$(exe)  :       %:%.o
	gcc -O2 -g -o $@ $^ -L../src -lzlog -lpthread -Wl,-rpath ../src

.c.o	:
	gcc -O2 -g -Wall -D_GNU_SOURCE -o $@ -c $< -I. -I../src

clean	:
	rm -f press.log* *.o $(exe)

.PHONY : clean all
