#ifndef CLIENTSOCK_H
#define CLIENTSOCK_H

#include "global.h"
#include "basesock.h"
#include "fingerprint.h"
#include "strings.h"

class DLL ClientSock: public BaseSock
{
public:

	ClientSock(void);
	~ClientSock();

	void ClearBuffer(void);
	int Init(void);
	int Init(bool createSock);
	void Close(void);
	string fingerprint(void);
	string cipherlist(void);
	int Ident(string ip, int listenport, int clientport, int timeout, string &result, string bindip);
	void ReadLoop(ClientSock &cs);
	void FastReadLoop(ClientSock &cs);
	int Connect(string ip, int port);

	// properties
	string socksIp(void);
	void socksIp(string socksIp);
	int socksPort(void);
	void socksPort(int socksPort);
	string socksPass(void);
	void socksPass(string socksPass);
	string socksUser(void);
	void socksUser(string socksUser);
	bool socksSsl(void);
	void socksSsl(bool socksSsl);
	bool useSocks(void);
	void useSocks(bool useSocks);
  bool ipv6(void);


protected:
	string _socksIp;
	int _socksPort;
	string _socksPass;
	string _socksUser;
	bool _socksSsl;
	bool _useSocks;
	bool _ipv6;
};


#endif
