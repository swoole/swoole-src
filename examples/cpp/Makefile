all: co repeat test_server
	
co: co.cc
	g++ co.cc -I../.. -I../../include -DHAVE_CONFIG_H -L../../lib -lswoole -o co -g
repeat: repeat.cc
	g++ repeat.cc -I../.. -I../../include -DHAVE_CONFIG_H -L../../lib -lswoole -o repeat -g
test_server: test_server.cc
	g++ test_server.cc -I../.. -I../../include -DHAVE_CONFIG_H -L../../lib -lswoole -o test_server -g
clean:
	rm -f co repeat test_server
