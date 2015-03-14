#include "serversock.h"


ServerSock::ServerSock(void)
{
	ssl = NULL;	
}

ServerSock::~ServerSock()
{
	Close();	
	ERR_remove_state(0);	
}

int ServerSock::Init()
{
	if(!GetSock(sock)) return 0;
	buffer = new char [_buffersize];
	if(buffer == NULL) return 0;	
	return 1;
}

int ServerSock::Listen(int pending)
{	
	if (listen(sock, pending) == -1)
	{
		return 0;
	}
	return 1;
}

void ServerSock::Close()
{
	if (ssl != NULL) 
	{		
		SSL_shutdown(ssl);					
	}
	if (ssl != NULL) 
	{
		SSL_free(ssl); 
		ssl = NULL; 
	}
	
	_Close(sock);
	if(buffer != NULL)
	{		
		delete [] buffer;
		buffer = NULL;
	}
}

int ServerSock::Accept(ClientSock &cs,string &ip, int &port)
{
	return _Accept(sock,cs.sock,ip,port,0);
}

int ServerSock::Accept(ClientSock &cs,string &ip, int &port, int timeout)
{
	return _Accept(sock,cs.sock,ip,port,timeout);
}
