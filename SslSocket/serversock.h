#ifndef SERVERSOCK_H
#define SERVERSOCK_H

#include "global.h"
#include "basesock.h"
#include "clientsock.h"

class DLL ServerSock: public BaseSock
{
public:

	ServerSock(void);
	~ServerSock();
	int Listen(int pending);
	int Init(void);
	void Close(void);
	int Accept(ClientSock &cs,string &ip, int &port);
	int Accept(ClientSock &cs,string &ip, int &port, int timeout);

protected:
	
	
};

#endif
