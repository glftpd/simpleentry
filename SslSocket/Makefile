CPPFLAGS = -fPIC -W -Wall -g -I/usr/local/ssl/include 

.cpp.o   :
	 g++ -c $(CPPFLAGS) $< -o $@
	 

all: callback.o dh1080.o fingerprint.o lock.o config.o basesock.o clientsock.o serversock.o strings.o thread.o
	g++ -shared -o libSslSocket.so callback.o dh1080.o fingerprint.o lock.o config.o basesock.o clientsock.o serversock.o strings.o thread.o -lpthread -lssl -lcrypto
	ar rcs libSslSocket.a *.o
	cp libSslSocket.* ../bin
clean:
	rm -rf *.o
install:
	cp ../bin/libSslSocket.* /usr/lib/
