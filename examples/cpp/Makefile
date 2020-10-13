all: co repeat
	
co: co.cc
	g++ co.cc -I../.. -I../../include -DHAVE_CONFIG_H -L../../lib -lswoole -o co -g
repeat: repeat.cc
	g++ repeat.cc -I../.. -I../../include -DHAVE_CONFIG_H -L../../lib -lswoole -o repeat -g
clean:
	rm -f co repeat
