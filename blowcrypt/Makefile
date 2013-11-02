CPPFLAGS = -W -Wall -g -I/usr/local/ssl/include -I../SslSocket

.cpp.o   :
	 g++ -c $(CPPFLAGS) $< -o $@
	 

all: main.o
	g++ main.o -o ../bin/blowcrypt -lSslSocket -lssl -lcrypto -ldl -lz -L../bin;strip ../bin/blowcrypt
	
static: main.o
	g++ main.o -o ../bin/blowcrypt-static -static -lSslSocket -lssl -lcrypto -ldl -lz -L../bin;strip ../bin/blowcrypt-static
	
clean:
	rm *.o;rm ../bin/blowcrypt*