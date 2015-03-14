#ifndef PASVTHREAD_H
#define PASVTHREAD_H

#include "global.h"
#include "basesock.h"
#include "clientsock.h"
#include "serversock.h"
#include "thread.h"
#include "options.h"

class PasvTrafficThread: public Thread
{
public:
	PasvTrafficThread(Options options, string siteip, int siteport);	

	bool InitSite();	
	bool InitListen(int listenPort);

	void loop(void);	

	~PasvTrafficThread(void);

protected:
	ClientSock clientsock;
	ClientSock sitesock;
	ServerSock listensock;

	Options options;
	string siteip;
	int siteport;
};


#endif
