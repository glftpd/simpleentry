CPPFLAGS = -fPIC -W -Wall -g -I/usr/local/ssl/include -I../SslSocket

.cc.o   :
	 g++ -c $(CPPFLAGS) $< -o $@
	 

all: main.o
	g++ main.o -o ../bin/entry -lSslSocket -lssl -lcrypto -ldl -lpthread -lz -L../bin;strip ../bin/entry

debug: main.o
	g++ main.o -o ../bin/entry -lSslSocket -lssl -lcrypto -ldl -lpthread -lz -L../bin

static: main.o
	g++ main.o -o ../bin/entry-static -static -lSslSocket -lssl -lcrypto -ldl -lpthread -lz -L../bin;strip ../bin/entry-static
	
clean:
	rm -rf *.o;rm -rf ../bin/entry;rm -rf ../bin/entry-static