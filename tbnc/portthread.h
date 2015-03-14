#ifndef PORTTHREAD_H
#define PORTTHREAD_H

#include "global.h"
#include "basesock.h"
#include "clientsock.h"
#include "serversock.h"
#include "thread.h"
#include "options.h"

class PortTrafficThread: public Thread
{
public:
	PortTrafficThread(Options *options, string siteip, int siteport);	

	bool InitSite();
	bool InitPort(string activeip,  int activeport);	

	void loop(void);	

	~PortTrafficThread();	

protected:
	ClientSock clientsock;
	ClientSock sitesock;

	Options *options;	
	string siteip;
	int siteport;
	string activeip;
	int activeport;
};


#endif
