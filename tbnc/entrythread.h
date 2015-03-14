#ifndef ENTRYTHREAD_H
#define ENTRYTHREAD_H

#include "global.h"
#include "basesock.h"
#include "clientsock.h"
#include "serversock.h"
#include "thread.h"
#include "pasvthread.h"
#include "portthread.h"
#include "options.h"

class EntryThread: public Thread
{
public:
	ClientSock cs;
	ClientSock sitesock;
	string clientip;
	int clientport;
	
	EntryThread(Options options);	
	
	// main loop
	void loop(void);	

	~EntryThread(void);

protected:
	// check reply for siteip - should never reach user
	bool checkReply(string reply);	

	// do ssl handshake
	bool doSsl(int type);
	
	// handle site replies
	bool doSite();	

	// handle user commands
	bool doUser();	

	// handle PASV command
	bool doPasv();

	// handle CPSV command
	bool doCpsv();

	// handle PORT command
	bool doPort(string portCmd);	

	Options options;
};



#endif
