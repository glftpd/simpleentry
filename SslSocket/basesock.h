#ifndef BASESOCK_H
#define BASESOCK_H


#include "global.h"
#include "lock.h"
#include "callback.h"


class DLL BaseSock
{

friend class ClientSock;
friend class ServerSock;

public:

	BaseSock(void);

	~BaseSock();

	// local config options
	int buffersize(void);
	void buffersize(int);
	int connecttimeout(void);
	void connecttimeout(int);
	int readwritetimeout(void);
	void readwritetimeout(int);
	int retrycount(void);
	void retrycount(int);

	// static config options
	static int Buffersize(void);
	static void Buffersize(int);
	static int Connecttimeout(void);
	static void Connecttimeout(int);
	static int Readwritetimeout(void);
	static void Readwritetimeout(int);
	static int Retrycount(void);
	static void Retrycount(int);
	static int SndRcvBufSize(void);
	static void SndRcvBufSize(int);
	static int Delay(void);
	static void Delay(int);	

	virtual int Init(void) {return 0;} // make this class abstract
	int Bind(string ip, int port);
	int _Connect(string ip, int port, bool &ipv6);
	int _Connect5(string ip, int port, string socksIp, int socksPort, string socksUser, string socksPass, bool socksSsl, bool &ipv6, int &status);

	int CanRead(int timeout);
	int ReadLine(string &str);
	int WriteLine(string str);
	int Read(char *buffer,int &nrbytes);
	int FastRead(char *buffer,int &nrbytes);
	int Write(char *data,int nrbytes);
	int FastWrite(char *data,int nrbytes);
	int BlockWrite(char *data,int nrbytes);
	int BlockRead(char *buffer, int &nrbytes);
	struct sockaddr_in6 GetIp(string ip, int port);
	string GetIpStr(string ip);

	void setquit(int quit);
	int shouldquit(void);

	char *buffer;	

	int sock;

	static int BaseInit();
	static int BaseSslInit(string certfile, string dhfile);
	static SSL_CTX *clientctx;
	static SSL_CTX *serverctx;
	static DH *globaldh;
	static SSL_CTX *getctx(void);
	int SslAccept(string cipher);
	int SslConnect(string cipher);
	

protected:
	
	
	int _shouldquit;
	SSL *ssl;
	
	int SocketOption(int &,int);
	int setnonblocking(int);
	int setblocking(int);
	int GetSock(int &);
	int _Close(int &);
	void correctReply(string &in);
	int _Accept(int listensock,int &newsock,string &clientip,int &clientport,int sec);
	int setreuse(int &socket);
	int setNoDelay(int &sock);
	int setBufSize(int &sock);
	void Wait(int milliseconds);
	Lock lock;

	// local config vars - initialized with global defaults - can be overridden for single objects
	int _buffersize;
	int _connecttimeout;	
	int _readwritetimeout;
	int _retrycount;

	// static vars for global defaults
	static int __buffersize;
	static int __connecttimeout;
	static int __readwritetimeout;
	static int __retrycount;
	static int __sndrcvbufsize;
	static int __delay;
};


#endif
