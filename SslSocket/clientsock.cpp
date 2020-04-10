#include "clientsock.h"
#include <cstring>

ClientSock::ClientSock(void)
{
	buffer = NULL;
	ssl = NULL;
  _ipv6 = false;
	_socksIp = "";
	_socksPort = 0;
	_socksUser = "";
	_socksPass = "";
	_socksSsl = false;
	_useSocks = false;
}

void ClientSock::ClearBuffer()
{
	memset(buffer,0,_buffersize);
}

ClientSock::~ClientSock()
{
	Close();	
	ERR_remove_state(0);	
}

int ClientSock::Init()
{
	return Init(true);
}

int ClientSock::Init(bool createSock)
{
	setquit(0);
	if(createSock)
	{
		if(!GetSock(sock)) return 0;
	}
	buffer = new char [_buffersize];
	if(buffer == NULL) return 0;
	return 1;
}

string ClientSock::fingerprint()
{	
	return _fingerprint(ssl);
}

string ClientSock::cipherlist()
{	
	string str(SSL_get_cipher(ssl));
	return str;
}

void ClientSock::Close()
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

int ClientSock::Ident(string ip, int listenport, int clientport, int timeout, string &result, string bindip)
{
	result = "*";
	ClientSock cs;
	if(!cs.Init()) return 0;
	cs.connecttimeout(timeout);
	if(bindip != "") cs.Bind(bindip,0);
	if(!cs.Connect(ip,113))
	{
		return 0;
	}
	stringstream ss;
	ss << clientport << " , " << listenport << "\r\n";
	if(!cs.WriteLine(ss.str()))
	{
		return 0;
	}
	string str;
	if(!cs.ReadLine(str))
	{
		return 0;
	}
	cs.Close();
	vector<string> res;
	split(res,str,':',false);
	if(res.size() == 4)
	{
		result = trim(res[3]);
	}
	else
	{		
		return 0;
	}	
	return 1;
}

void ClientSock::ReadLoop(ClientSock &cs)
{	
	int size = 0;
	if(cs.buffersize() != buffersize()) return;
	fd_set readfds;
	fd_set errorfds;
	struct timeval tv;

	while(true)
	{
		if(shouldquit() == 1) return;

		tv.tv_sec = 0;
		tv.tv_usec = 10000;

		FD_ZERO(&readfds);
		FD_ZERO(&errorfds);
		FD_SET(sock, &readfds);
		FD_SET(cs.sock, &readfds);
		FD_SET(sock, &errorfds);
		FD_SET(cs.sock, &errorfds);
		
		int tmpsock = sock;
		if (sock < cs.sock)
		{
			tmpsock = cs.sock;
		}		
				
		if (select(tmpsock+1, &readfds, NULL, &errorfds, &tv) == -1)
		{			
			return;
		}
		if(FD_ISSET(sock, &errorfds) || FD_ISSET(cs.sock, &errorfds))
		{			
			return;
		}
		if (FD_ISSET(sock, &readfds))
		{			
			if(!Read(buffer,size))
			{				
				return;
			}
			if(!cs.Write(buffer,size))
			{				
				return;
			}
		}
		else if (FD_ISSET(cs.sock, &readfds))
		{			
			if(!cs.Read(buffer,size))
			{				
				return;
			}
			if(!Write(buffer,size))
			{				
				return;
			}
		}		
	}
}

void ClientSock::FastReadLoop(ClientSock &cs)
{	
	int size = 0;
	if(cs.buffersize() != buffersize()) return;
	fd_set readfds;
	fd_set errorfds;
	struct timeval tv;

	while(true)
	{
		if(shouldquit() == 1) return;

		tv.tv_sec = 0;
		tv.tv_usec = 10000;

		FD_ZERO(&readfds);
		FD_ZERO(&errorfds);
		FD_SET(sock, &readfds);
		FD_SET(cs.sock, &readfds);
		FD_SET(sock, &errorfds);
		FD_SET(cs.sock, &errorfds);
		
		int tmpsock = sock;
		if (sock < cs.sock)
		{
			tmpsock = cs.sock;
		}		
				
		if (select(tmpsock+1, &readfds, NULL, &errorfds, &tv) == -1)
		{			
			return;
		}
		if(FD_ISSET(sock, &errorfds) || FD_ISSET(cs.sock, &errorfds))
		{			
			return;
		}
		if (FD_ISSET(sock, &readfds))
		{			
			if(!FastRead(buffer,size))
			{				
				return;
			}
			if(!cs.FastWrite(buffer,size))
			{				
				return;
			}
		}
		else if (FD_ISSET(cs.sock, &readfds))
		{			
			if(!cs.FastRead(buffer,size))
			{				
				return;
			}
			if(!FastWrite(buffer,size))
			{				
				return;
			}
		}		
	}
}

string ClientSock::socksIp(void)
{
	return _socksIp;
}

void ClientSock::socksIp(string socksIp)
{
	_socksIp = socksIp;
}

int ClientSock::socksPort(void)
{
	return _socksPort;
}

void ClientSock::socksPort(int socksPort)
{
	_socksPort = socksPort;
}

string ClientSock::socksUser(void)
{
	return _socksUser;
}

void ClientSock::socksUser(string socksUser)
{
	_socksUser = socksUser;
}

string ClientSock::socksPass(void)
{
	return _socksPass;
}

void ClientSock::socksPass(string socksPass)
{
	_socksPass = socksPass;
}

bool ClientSock::socksSsl(void)
{
	return _socksSsl;
}

void ClientSock::socksSsl(bool socksSsl)
{
	_socksSsl = socksSsl;
}

bool ClientSock::useSocks(void)
{
	return _useSocks;
}

void ClientSock::useSocks(bool useSocks)
{
	_useSocks = useSocks;
}

bool ClientSock::ipv6(void)
{
	return _ipv6;
}

int ClientSock::Connect(string ip, int port)
{
	if(!useSocks())
	{
		return _Connect(ip, port, _ipv6);
	}
	else
	{
		int status;
		return _Connect5(ip, port, socksIp(), socksPort(), socksUser(), socksPass(), socksSsl(), _ipv6, status);
	}
}
