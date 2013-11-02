CPPFLAGS = -W -Wall -g -I/usr/local/ssl/include -I../SslSocket

.cpp.o   :
	 g++ -c $(CPPFLAGS) $< -o $@
	 

all: main.o entrythread.o options.o pasvthread.o portthread.o
	g++ main.o entrythread.o options.o pasvthread.o portthread.o -o ../bin/tbnc -lSslSocket -lssl -lcrypto -ldl -lpthread -lz -L../bin;strip ../bin/tbnc

debug: main.o entrythread.o options.o pasvthread.o portthread.o
	g++ main.o entrythread.o options.o pasvthread.o portthread.o -o ../bin/tbnc -lSslSocket -lssl -lcrypto -ldl -lpthread -lz -L../bin

static: main.o entrythread.o options.o pasvthread.o portthread.o
	g++ main.o entrythread.o options.o pasvthread.o portthread.o -o ../bin/tbnc-static -static -lSslSocket -lssl -lcrypto -ldl -lpthread -lz -L../bin;strip ../bin/tbnc-static
	
clean:
	rm -rf *.o;rm -rf ../bin/tbnc;rm -rf ../bin/tbnc-static