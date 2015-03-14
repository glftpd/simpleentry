CPPFLAGS = -fPIC -W -Wall -g -I/usr/local/ssl/include -I../SslSocket

.cpp.o   :
	 g++ -c $(CPPFLAGS) $< -o $@
	 

all: main.o
	g++ main.o -o ../bin/simplesocks -lSslSocket -lssl -lcrypto -ldl -lpthread -lz -L../bin;strip ../bin/simplesocks

debug: main.o
	g++ main.o -o ../bin/simplesocks -lSslSocket -lssl -lcrypto -ldl -lpthread -lz -L../bin

static: main.o
	g++ main.o -o ../bin/simplesocks-static -static -lSslSocket -lssl -lcrypto -ldl -lpthread -lz -L../bin;strip ../bin/simplesocks-static
	
clean:
	rm -rf *.o;rm -rf ../bin/simplesocks;rm -rf ../bin/simplesocks-static