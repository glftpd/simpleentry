#include "basesock.h"
#include "fingerprint.h"

// set global defaults
int BaseSock::__buffersize = 65536;
int BaseSock::__connecttimeout = 15;
int BaseSock::__readwritetimeout = 15;
int BaseSock::__retrycount = 15;
int BaseSock::__sndrcvbufsize = 625000;
int BaseSock::__delay = 5;
SSL_CTX *BaseSock::serverctx = NULL;
SSL_CTX *BaseSock::clientctx = NULL;
DH *BaseSock::globaldh = NULL;

BaseSock::BaseSock(void)
{
	_buffersize = BaseSock::__buffersize;
	_readwritetimeout = BaseSock::__readwritetimeout;
	_retrycount = BaseSock::__retrycount;
	_connecttimeout = BaseSock::__connecttimeout;
	buffer = NULL;
	_shouldquit = 0;
	ssl = NULL;	
	sock = -1;
}

BaseSock::~BaseSock()
{
	
}

// local config options

int BaseSock::buffersize()
{
	return _buffersize;
}

void BaseSock::buffersize(int size)
{
	_buffersize = size;
}

int BaseSock::connecttimeout()
{
	return _connecttimeout;
}

void BaseSock::connecttimeout(int timeout)
{
	_connecttimeout = timeout;
}

int BaseSock::readwritetimeout()
{
	return _readwritetimeout;
}

void BaseSock::readwritetimeout(int timeout)
{
	_readwritetimeout = timeout;
}

int BaseSock::retrycount()
{
	return _retrycount;
}

void BaseSock::retrycount(int count)
{
	_retrycount = count;
}

// global config options

int BaseSock::Buffersize()
{
	return BaseSock::__buffersize;
}

void BaseSock::Buffersize(int size)
{
	BaseSock::__buffersize = size;
}

int BaseSock::SndRcvBufSize()
{
	return BaseSock::__sndrcvbufsize;
}

void BaseSock::SndRcvBufSize(int size)
{
	BaseSock::__sndrcvbufsize = size;
}

int BaseSock::Connecttimeout()
{
	return BaseSock::__connecttimeout;
}

void BaseSock::Connecttimeout(int timeout)
{
	BaseSock::__connecttimeout = timeout;
}

int BaseSock::Readwritetimeout()
{
	return BaseSock::__readwritetimeout;
}

void BaseSock::Readwritetimeout(int timeout)
{
	BaseSock::__readwritetimeout = timeout;
}

int BaseSock::Retrycount()
{
	return BaseSock::__retrycount;
}

void BaseSock::Retrycount(int count)
{
	BaseSock::__retrycount = count;
}

void BaseSock::Delay(int delay)
{
	BaseSock::__delay = delay;
}

int BaseSock::Delay(void)
{
	return BaseSock::__delay;
}

// other functions

int BaseSock::_Connect(string host,int port)
{	
	
	struct sockaddr_in adr;
	adr = GetIp(host,port);
	if(!setnonblocking(sock))
	{
		return 0;
	}
	int rc;
	if((rc = connect(sock, (struct sockaddr *)&adr, sizeof(adr))) < 0)
	{
#ifdef _WIN32
		int err = WSAGetLastError();
		
		if(err != WSAEINPROGRESS && err != WSAEWOULDBLOCK)
#else
		if(errno != EINPROGRESS)
#endif
		{				
			return 0;
		}
	}
	if (rc != 0) // ==0 -> connect completed immediately
	{
		fd_set writefds,readfds,errorfds;
		for(int i=0; i < connecttimeout() * 20;i++)
		{
			FD_ZERO(&writefds);
			FD_ZERO(&readfds);
			FD_ZERO(&errorfds);
			FD_SET(sock, &writefds);
			FD_SET(sock, &readfds);
			FD_SET(sock, &errorfds);
			
			struct timeval tv;
			tv.tv_sec = 0;
			tv.tv_usec = 50000;
			int res = select(sock+1, &readfds, &writefds, &errorfds, &tv);
			if (res < 0)
			{						
				return 0;
			}
			else if(res == 0)
			{			
				if(shouldquit() == 1) 
				{						
					return 0;
				}
			}
			if(FD_ISSET(sock,&errorfds))
			{
				return 0;
			}
			if(FD_ISSET(sock,&readfds) || FD_ISSET(sock,&writefds))
			{
				int err;
				
#ifdef _WIN32
		int errlen = sizeof(err);
		if(getsockopt(sock,SOL_SOCKET,SO_ERROR,(char *)&err,&errlen) < 0)
#else
		socklen_t errlen = sizeof(err);
		if(getsockopt(sock,SOL_SOCKET,SO_ERROR,&err,&errlen) < 0)
#endif
				{						
					return 0;
				}
				if(err)
				{						
					return 0;
				}
				if(!SocketOption(sock,SO_KEEPALIVE))
				{						
					return 0;
				}
				if(!setNoDelay(sock))
				{
					return 0;
				}
				if(!setBufSize(sock))
				{
					return 0;
				}		
				return 1;
			}
		}
	}
	else
	{
		int err;
		
#ifdef _WIN32
		int errlen = sizeof(err);
		if(getsockopt(sock,SOL_SOCKET,SO_ERROR,(char *)&err,&errlen) < 0)
#else
		socklen_t errlen = sizeof(err);
		if(getsockopt(sock,SOL_SOCKET,SO_ERROR,&err,&errlen) < 0)
#endif
		{				
			return 0;
		}
		if(err)
		{				
			return 0;
		}
		if(!SocketOption(sock,SO_KEEPALIVE))
		{				
			return 0;
		}
		if(!setNoDelay(sock))
		{
			return 0;
		}
		if(!setBufSize(sock))
		{
			return 0;
		}
		return 1;
	}
	
	return 0;
}

int BaseSock::_Connect5(string ip, int port, string socksIp, int socksPort, string socksUser, string socksPass, bool socksSsl, int &status)
{
	if(!_Connect(socksIp, socksPort))
	{
		status = 1; // socks connect failed
		return 0;
	}
	
	if(buffer == NULL) return 0;

	int rc = 0;
    buffer[0] = 5;
    buffer[1] = 1;
    buffer[2] = 2;

    if (!Write(buffer, 3) || shouldquit())
    {
		status = 2; // read/write error
        return 0;
    }
    if (!Read(buffer, rc) || shouldquit())
    {
		status = 2;
        return 0;
    }
    if (rc != 2 || shouldquit())
    {
		status = 3; // general error
        return 0;
    }
    if (buffer[0] != 5 || buffer[1] != 2 || shouldquit())
    {
		status = 3;
        return 0;
    }
    if (socksPass.length() > 255 || socksUser.length() > 255 || shouldquit())
    {
		status = 3;
        return 0;
    }
    buffer[0] = 1;
    buffer[1] = socksUser.length();
        
    for (unsigned int i = 0; i < socksUser.length(); i++)
    {
        buffer[i + 2] = socksUser[i];
    }
    buffer[socksUser.length() + 2] = socksPass.length();
    
    for (unsigned int i = 0; i < socksPass.length(); i++)
    {
        buffer[i + 3 + socksUser.length()] = socksPass[i];
    }
    if (!Write(buffer, 3 + socksUser.length() + socksPass.length()) || shouldquit())
    {
		status = 2;
        return 0;
    }
    if (!Read(buffer, rc) || shouldquit())
    {
		status = 2;
        return 0;
    }
    if (rc != 2 || shouldquit())
    {
		status = 3;
        return 0;
    }
    if (buffer[0] != 1 || buffer[1] != 0 || shouldquit())
    {
        // user/pass wrong
        status = 4;
        return 0;
    }
    // connect request
    buffer[0] = 5;
    buffer[1] = 1;
    buffer[2] = 0;
    buffer[3] = 1;

	struct sockaddr_in adr;
	adr = GetIp(ip,port);
	//memcpy(&adr.sin_addr.s_addr,buffer+4,4);
	memcpy(buffer+4,&adr.sin_addr.s_addr,4);
    buffer[8] = (char)(port / 256);
    buffer[9] = (char)(port % 256);

    if (!Write(buffer, 10))
    {
        status = 2;
        return 0;
    }
    if (!Read(buffer, rc) || shouldquit())
    {
		status = 2;
        return 0;
    }
    if (rc != 10 || shouldquit())
    {
		status = 3;
        return 0;
    }
	if(socksSsl)
	{
		if(!SslConnect("")) return 0;
	}
	return 1;
}

int BaseSock::CanRead(int timeout)
{
	if (sock < 0) return 0;
	fd_set readfds;
	fd_set errorfds;
	struct timeval tv;

	if(timeout == 0)
	{
		while(true)
		{
			if(shouldquit()) return 0;
			if (sock < 0) return 0;
			tv.tv_sec = 0;
			tv.tv_usec = 10000;
			FD_ZERO(&readfds);
			FD_SET(sock,&readfds);
			FD_ZERO(&errorfds);
			FD_SET(sock,&errorfds);
		
			if (select(sock+1,&readfds,NULL,&errorfds,&tv) == -1)
			{	
				return 0;
			}
			if(FD_ISSET(sock,&errorfds))
			{
				return 0;
			}
			if (FD_ISSET(sock,&readfds))
			{
				return 1;
			}
		}
	}
	else
	{	
		tv.tv_sec = timeout;
		tv.tv_usec = 0;
		FD_ZERO(&readfds);
		FD_SET(sock,&readfds);
		FD_ZERO(&errorfds);
		FD_SET(sock,&errorfds);
		
		if (select(sock+1,&readfds,NULL,&errorfds,&tv) == -1)
		{	
			return 0;
		}
		if(FD_ISSET(sock,&errorfds))
		{
			return 0;
		}
		if (FD_ISSET(sock,&readfds))
		{
			return 1;
		}
		else
		{
			return 0;
		}
	}
}

int BaseSock::GetSock(int &sock)
{		
	if((sock = socket(AF_INET,SOCK_STREAM,0)) == -1)
	{
		sock = -1;
		
		return 0;
	}
	
	return 1;
}

int BaseSock::_Close(int &sock)
{	
	if(sock > 0)
	{	
		shutdown(sock,2);
#ifdef _WIN32
		if(closesocket(sock) != -1)
#else
		if(close(sock) != -1)
#endif
		{
			sock = -1;				
			return 1;
		}
		else
		{
			sock = -1;				
			return 0;
		}
	}
	else
	{
		sock = -1;			
		return 1;
	}
}

int BaseSock::SocketOption(int &sock,int option)
{
	int yes = 1;
#ifdef _WIN32
	if (setsockopt(sock,SOL_SOCKET,option,(const char *)&yes,sizeof(int)) != 0)
	{		
		return 0;
	}
#else
	if (setsockopt(sock,SOL_SOCKET,option,&yes,sizeof(int)) != 0)
	{		
		return 0;
	}
#endif

	return 1;
}

int BaseSock::setNoDelay(int &sock)
{
	int yes = 1;
#ifdef _WIN32
	if (setsockopt(sock,IPPROTO_TCP,TCP_NODELAY,(const char *)&yes,sizeof(int)) != 0)
	{		
		return 0;
	}
#else
	if (setsockopt(sock,IPPROTO_TCP,TCP_NODELAY,&yes,sizeof(int)) != 0)
	{		
		return 0;
	}
#endif

	return 1;
}

int BaseSock::setBufSize(int &sock)
{	
#ifdef _WIN32
	if (setsockopt(sock,SOL_SOCKET, SO_SNDBUF,(const char *)&__sndrcvbufsize,sizeof(__sndrcvbufsize)) != 0)
	{		
		return 0;
	}
	if (setsockopt(sock,SOL_SOCKET, SO_RCVBUF,(const char *)&__sndrcvbufsize,sizeof(__sndrcvbufsize)) != 0)
	{		
		return 0;
	}
#else
	if (setsockopt(sock,SOL_SOCKET, SO_SNDBUF,&__sndrcvbufsize,sizeof(__sndrcvbufsize)) != 0)
	{		
		return 0;
	}
	if (setsockopt(sock,SOL_SOCKET, SO_RCVBUF,&__sndrcvbufsize,sizeof(__sndrcvbufsize)) != 0)
	{		
		return 0;
	}
#endif

	return 1;
}

int BaseSock::setnonblocking(int socket)
{	
#ifdef _WIN32
	// If iMode = 0, blocking is enabled; 
	// If iMode != 0, non-blocking mode is enabled.
	u_long iMode = 1;
	if(ioctlsocket(socket, FIONBIO, &iMode) == 0)
	{
		return 1;
	}
	else
	{
		return 0;
	}
#else
	int flags;
	if((flags = fcntl(socket, F_GETFL, 0)) == -1)
	{ 		
		return 0;
	}
	flags |= O_NONBLOCK;
	if (fcntl(socket, F_SETFL, flags) == -1)
	{		
		return 0;
	}
	return 1;
#endif
}

int BaseSock::setblocking(int socket)
{	
#ifdef _WIN32
	// If iMode = 0, blocking is enabled; 
	// If iMode != 0, non-blocking mode is enabled.
	u_long iMode = 0;
	if(ioctlsocket(socket, FIONBIO, &iMode) == 0)
	{
		return 1;
	}
	else
	{
		return 0;
	}
#else
	int flags;
	if((flags = fcntl(socket, F_GETFL, 0)) == -1)
	{ 		
		return 0;
	}
	flags &= ~O_NONBLOCK;
	if (fcntl(socket, F_SETFL, flags) == -1)
	{		
		return 0;
	}
	return 1;
#endif
}

int BaseSock::setreuse(int &socket)
{
	return SocketOption(socket, SO_REUSEADDR);
}

struct sockaddr_in BaseSock::GetIp(string ip,int port)
{
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	unsigned long lip = inet_addr(ip.c_str());
	if(lip == INADDR_NONE)
	{
		struct hostent *he;
	
		if((he = gethostbyname(ip.c_str())) == NULL)
		{	
			lip = inet_addr("0.0.0.0");
			addr.sin_addr.s_addr = lip;
		}
		else
		{
			addr.sin_addr = *(struct in_addr*)he->h_addr;
		}
	}
	else
	{
		addr.sin_addr.s_addr = lip;
	}
	addr.sin_port = htons(port);
	memset(&(addr.sin_zero), '\0', 8);
	return addr;
}

string BaseSock::GetIpStr(string ip)
{
	sockaddr_in adr = GetIp(ip,0);
	string tmpip(inet_ntoa(adr.sin_addr));
	return tmpip;
}

int BaseSock::ReadLine(string &str)
{
	str = "";
	string tmp = "";
	fd_set readfds;
	fd_set errorfds;
	struct timeval tv;
	int rc = 0;	
	int count = 0;
	
	while(1)
	{	
		bool pend = false;
		if(ssl != NULL)
		{
			if(SSL_pending(ssl) > 0) pend = true;
		}
		memset(buffer,0,buffersize());
		tv.tv_sec = readwritetimeout();
		tv.tv_usec = 0;
		FD_ZERO(&readfds);
		FD_SET(sock,&readfds);
		FD_ZERO(&errorfds);
		FD_SET(sock,&errorfds);
		if(str.length() == 0)
		{
			if(!pend)
			{
				if (select(sock+1,&readfds,NULL,&errorfds,&tv) == -1)
				{				
					str = tmp;				
					stringstream ss;
					ss << str.length();								
					return 1;
				}
			}
		}
		else
		{
			if(!pend)
			{
				timeval tv;
				tv.tv_sec = 1;
				tv.tv_usec = 0;
				if (select(sock+1,&readfds,NULL,&errorfds,&tv) == -1)
				{				
					str = tmp;				
					stringstream ss;
					ss << str.length();								
					return 1;
				}
			}
		}
		if(FD_ISSET(sock,&errorfds))
		{
			return 0;
		}
		if (pend || FD_ISSET(sock,&readfds))
		{
			if (ssl == NULL)
			{
				rc = recv(sock,buffer,buffersize(),0);
			}
			else
			{
				rc = SSL_read(ssl,buffer,buffersize());
			}
			if (rc == 0)
			{
				if(ssl != NULL) SSL_get_error(ssl,rc); // clear ssl error queue
				return 0;
			}
			else if (rc < 0)
			{
				if(count == retrycount()) { return 0; } // not more then x retries

				if (ssl != NULL)
				{	
					int err = SSL_get_error(ssl,rc);
					
					if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_X509_LOOKUP) 
					{
						Wait(__delay);
						count++;
						continue;
					}
					else
					{							
						return 0;
					}
				}
				else
				{
#ifdef _WIN32
					int err = WSAGetLastError();
#else
					int err = errno;
#endif
					if(err == EAGAIN)
					{
						Wait(__delay);
						count++;
						continue;
					}
					else
					{
						return 0;
					}
				}
			}
			else
			{
				count = 0;
				char *tmpstr;
				tmpstr = new char[rc+1];
				memcpy(tmpstr,buffer,rc);
				tmpstr[rc] = '\0';
				
				tmp += tmpstr;
				
				delete [] tmpstr;
				if (rc < buffersize())
				{
					// reached end of line?
					if (tmp[tmp.length() - 1] == '\n')
					{		
						// fix missing \r's
						correctReply(tmp);		
						str = tmp;		
						
						return 1;		
													
					}
					str = tmp;
					return 1;
				}
			}
		}
		else
		{				
			return 0;
		}
	}
}

void BaseSock::correctReply(string &in)
{
	string tmp;
	for(int i=0;i < (int)in.length();i++)
	{
		if(in[i] != '\n')
		{
			tmp += in[i];
		}
		else
		{
			if(i>0)
			{
				if(in[i-1] != '\r')
				{
					tmp += '\r';
					tmp += in[i];
				}
				else
				{
					tmp += in[i];
				}
			}
			else if(i == 0)
			{
				tmp += '\r';
				tmp += in[i];
			}
		}
	}
	in = tmp;
}

int BaseSock::WriteLine(string s)
{	
		
	stringstream ss;
	ss << s.length();
		
	fd_set writefds;
	fd_set errorfds;
	struct timeval tv;

	int maxsize = buffersize(); // max size in bytes of packet
	int total = 0;
	int count = 0;
	int bytesleft = s.length();
	int blocksize;
	if (bytesleft > maxsize)
	{
		blocksize = maxsize;
	}
	else
	{
		blocksize = bytesleft;
	}
	int n=0,len=0;
	len = s.length();
	while(total < len)
	{
		tv.tv_sec = readwritetimeout();
		tv.tv_usec = 0;
		FD_ZERO(&writefds);
		FD_SET(sock,&writefds);
		FD_ZERO(&errorfds);
		FD_SET(sock,&errorfds);
		if (select(sock+1,NULL,&writefds,&errorfds,&tv) == -1)
		{	
			return 0;
		}
		if(FD_ISSET(sock,&errorfds))
		{
			return 0;
		}
		if (FD_ISSET(sock,&writefds))
		{
			if (!ssl)
			{
				n = send(sock,s.c_str()+total,blocksize,0);
			}
			else
			{
				n = SSL_write(ssl, s.c_str()+total, blocksize);
			}
		}
		if(n == 0)
		{
			if(ssl != NULL) SSL_get_error(ssl,n); // clear ssl error queue
			return 0;
		}
		else if (n < 0)
		{
			if(count == retrycount()) { return 0; } // not more then x retries

			if (ssl != NULL)
			{	
				int err = SSL_get_error(ssl,n);
				
				if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_X509_LOOKUP) 
				{
					Wait(__delay);
					count++;
					continue;
				}
				else
				{						
					return 0;
				}
			}
			else
			{
#ifdef _WIN32
					int err = WSAGetLastError();
#else
					int err = errno;
#endif
				if(err == EAGAIN)
				{
					Wait(__delay);
					count++;
					continue;
				}
				else
				{
					return 0;
				}
			}
		}
		count = 0;
		total += n;
		bytesleft -= n;
		if (bytesleft > maxsize)
		{
			blocksize = maxsize;
		}
		else
		{
			blocksize = bytesleft;
		}
	}
	
	if (bytesleft == 0)
	{	
		return 1;
	}
	else
	{	
		return 0;
	}
}

int BaseSock::shouldquit(void)
{
	int tmp;
	lock.lock();
	tmp = _shouldquit;
	lock.unlock();
	return tmp;
}

void BaseSock::setquit(int quit)
{
	lock.lock();
	_shouldquit = quit;
	lock.unlock();
}

int BaseSock::Bind(string ip,int port)
{
	struct sockaddr_in adr;
	if (ip != "")
	{
		adr = GetIp(ip,port);
	}
	else
	{		
		adr.sin_addr.s_addr = INADDR_ANY;
		adr.sin_port = htons(port);
		adr.sin_family = AF_INET;
		memset(&(adr.sin_zero), '\0', 8);
	}
	if(!setreuse(sock)) return 0;
	if(bind(sock,(struct sockaddr *)&adr, sizeof(struct sockaddr)) != 0)
	{		
		return 0;
	}
	return 1;
}

void BaseSock::Wait(int milliseconds)
{
#ifdef _WIN32
	Sleep(milliseconds);
#else
	usleep(milliseconds * 1000);
#endif
}

int BaseSock::Write(char *data,int nrbytes)
{	
	int total = 0;
	int bytesleft = nrbytes;
	int rc;
	int count = 0;
	
	fd_set data_writefds;
	fd_set errorfds;
	struct timeval tv;	

	
	while(total < nrbytes)
	{
		FD_ZERO(&data_writefds);
		FD_SET(sock,&data_writefds);
		FD_ZERO(&errorfds);
		FD_SET(sock,&errorfds);
		tv.tv_sec = readwritetimeout();
		tv.tv_usec = 0;
		if (select(sock+1, NULL, &data_writefds, &errorfds, &tv) < 1)
		{		
			return 0;
		}
		if(FD_ISSET(sock,&errorfds))
		{		
			return 0;
		}
		if (FD_ISSET(sock, &data_writefds))
		{				
			if(ssl == NULL)
			{		
				rc = send(sock,data+total,bytesleft,0);
			}
			else
			{
				rc = SSL_write(ssl,data+total,bytesleft);
			}
			if(rc > 0)
			{
				count = 0;
				total += rc;
				bytesleft -= rc;
			}
			else if (rc == 0)
			{
				if(ssl != NULL) SSL_get_error(ssl,rc); // clear ssl error queue
				return 0;
			}
			else
			{
				if(count == retrycount()) { return 0; } // not more then x retries

				if (ssl != NULL)
				{	
					int err = SSL_get_error(ssl,rc);
						
					if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_X509_LOOKUP) 
					{
						Wait(__delay);
						count++;
						continue; 
					}
					else
					{							
						return 0;
					}
				}
				else
				{
#ifdef _WIN32
				int err = WSAGetLastError();
#else
				int err = errno;
#endif
					if(err == EAGAIN)
					{
						Wait(__delay);
						count++;
						continue;
					}
					else
					{
						return 0;
					}
				}
			}
		}
		else
		{		
			return 0;
		}
	}
	return 1;	
}

int BaseSock::FastWrite(char *data,int nrbytes)
{	
	int total = 0;
	int bytesleft = nrbytes;
	int rc;
	int count = 0;

	while(total < nrbytes)
	{
		rc = send(sock,data+total,bytesleft,0);
		if(rc > 0)
		{
			count = 0;
			total += rc;
			bytesleft -= rc;
		}
		else if (rc == 0)
		{
			return 0;
		}
		else
		{
			if(count == retrycount()) { return 0; } // not more then x retries

#ifdef _WIN32
			int err = WSAGetLastError();
#else
			int err = errno;
#endif
			if(err == EAGAIN)
			{
				Wait(__delay);
				count++;
				continue;
			}
			else
			{
				return 0;
			}
		}
	}
	return 1;	
}

int BaseSock::Read(char *buffer,int &nrbytes)
{
	int count = 0;
	while(1)
	{
		bool pend = false;
		if(ssl != NULL)
		{
			if(SSL_pending(ssl) > 0) pend = true;
		}
		
		fd_set readfds;
		fd_set errorfds;
        FD_ZERO(&readfds);
        FD_SET(sock,&readfds);
		FD_ZERO(&errorfds);
        FD_SET(sock,&errorfds);
        struct timeval tv;
        tv.tv_sec = readwritetimeout();;
        tv.tv_usec = 0;

		if(!pend)
		{
			if (select(sock+1, &readfds, NULL, &errorfds, &tv) < 1)
	        {
				break;
	        }
		}
		if(FD_ISSET(sock,&errorfds))
		{
			break;
		}
		if(pend || FD_ISSET(sock, &readfds))
	    {
			int rc;		
			if (ssl == NULL)
			{
				rc = recv(sock,buffer,buffersize(),0);
  			}
			else
			{
				rc = SSL_read(ssl,buffer,buffersize());
			}
	  				
			if (rc > 0) 
			{ 
				count = 0;
				nrbytes = rc; 
				return 1; 
			}
			else  if(rc == 0)
			{
				if(ssl != NULL) SSL_get_error(ssl,rc); // clear ssl error queue
				nrbytes=0; 
				return 0; 
			}
			else
			{	
				if(count == retrycount()) { return 0; } // not more then x retries

				if (ssl != NULL)
				{
					int err = SSL_get_error(ssl,rc);
					
					if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_X509_LOOKUP) 
					{
						Wait(__delay);
						count++;
						continue;
					}
					else
					{						
						return 0;
					}
					
				}
				else
				{
					#ifdef _WIN32
					int err = WSAGetLastError();
#else
					int err = errno;
#endif
					if(err == EAGAIN)
					{
						Wait(__delay);
						count++;
						continue;
					}
					else
					{
						nrbytes=0;
						return 0;
					}
				}				
			}
		}
		else
		{
			break;
		}
	}
	return 0;
}

int BaseSock::FastRead(char *buffer,int &nrbytes)
{
	int count = 0;
	while(1)
	{
		int rc;
		rc = recv(sock,buffer,buffersize(),0);
	  				
		if (rc > 0) 
		{ 
			count = 0;
			nrbytes = rc; 
			return 1; 
		}
		else  if(rc == 0)
		{
			nrbytes=0; 
			return 0; 
		}
		else
		{	
			if(count == retrycount()) { return 0; } // not more then x retries
				
				#ifdef _WIN32
				int err = WSAGetLastError();
#else
				int err = errno;
#endif
				if(err == EAGAIN)
				{
					Wait(__delay);
					count++;
					continue;
				}
				else
				{
					nrbytes=0;
					return 0;
				}
		}
	}
	return 0;
}

int BaseSock::_Accept(int listensock,int &newsock,string &clientip,int &clientport,int sec)
{	
	fd_set readfds;
	fd_set errorfds;
	struct sockaddr_in adr;
	
	if(sec > 0)
	{
		if(!setnonblocking(listensock))
		{
			return 0;
		}
		for(int i=0; i < sec * 20;i++)
		{
			FD_ZERO(&readfds);
			FD_SET(listensock, &readfds);
			FD_ZERO(&errorfds);
			FD_SET(listensock, &errorfds);
			struct timeval tv;
			tv.tv_sec = 0;
			tv.tv_usec = 50000;
			int res;
			
			res =  select(listensock+1, &readfds, NULL, &errorfds, &tv);
			
			if (res < 0)
			{				
				return 0;
			}
			if(FD_ISSET(listensock,&errorfds))
			{
				return 0;
			}
			else if(res == 0)
			{
				if (shouldquit() == 1) 
				{					
					return 0;
				}
			}
			else
			{
				break;
			}
		}
	}
	else
	{
		// no timeout? block and wait
		if(!setblocking(listensock))
		{
			return 0;
		}
	}
	#ifdef _WIN32
		int size = sizeof(adr);		
	#else
		socklen_t size = sizeof(adr);		
	#endif

	
	if ((newsock = accept(listensock,(struct sockaddr *)&adr,&size)) == -1)
	{		
		return 0;
	}
	
	clientip = inet_ntoa(adr.sin_addr);
	clientport = ntohs(adr.sin_port);
	
	if(!setnonblocking(newsock))
	{
		return 0;
	}
	
	if(!SocketOption(newsock,SO_KEEPALIVE))
	{		
		return 0;
	}
	
	return 1;
}

int BaseSock::BaseInit()
{
	return _BaseInit();
}

static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
	if(preverify_ok == 2)
	{
		// do nothing
	}
	if(ctx == NULL)
	{
		// do nothing
	}
	return 1;
}

int BaseSock::BaseSslInit(std::string certfile, std::string dhfile)
{
	
	std::string sessionId("sslsock");
	
	serverctx = SSL_CTX_new(SSLv23_server_method());
	clientctx = SSL_CTX_new(SSLv23_client_method());

	if(serverctx == NULL || clientctx == NULL)
	{
		return 0;
	}

	SSL_CTX_set_default_verify_paths(serverctx);
	SSL_CTX_set_options(serverctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION | SSL_OP_SINGLE_DH_USE | SSL_OP_SINGLE_ECDH_USE | SSL_OP_CIPHER_SERVER_PREFERENCE);
	SSL_CTX_set_mode(serverctx,SSL_MODE_AUTO_RETRY);
	SSL_CTX_set_session_cache_mode(serverctx,SSL_SESS_CACHE_SERVER);
	SSL_CTX_set_session_id_context(serverctx,(const unsigned char*)sessionId.c_str(),sessionId.size());
	SSL_CTX_set_verify(serverctx,SSL_VERIFY_PEER,verify_callback);

	SSL_CTX_set_default_verify_paths(clientctx);
	SSL_CTX_set_options(clientctx,SSL_OP_ALL);
	SSL_CTX_set_mode(clientctx,SSL_MODE_AUTO_RETRY);
	SSL_CTX_set_session_cache_mode(clientctx,SSL_SESS_CACHE_OFF);
	SSL_CTX_set_verify(clientctx,SSL_VERIFY_PEER,verify_callback);

	if (!SSL_CTX_use_certificate_chain_file(serverctx,certfile.c_str()))
	{	
		return 0;
	}
	else 
	{	
		SSL_CTX_use_certificate_chain_file(clientctx,certfile.c_str());
		if (!SSL_CTX_use_PrivateKey_file(serverctx, certfile.c_str(), SSL_FILETYPE_PEM))
		{	
			return 0;
		}
		else
		{
			SSL_CTX_use_PrivateKey_file(clientctx, certfile.c_str(), SSL_FILETYPE_PEM);
		}
	}

	BIO *bio = NULL;
	bio = BIO_new_file(dhfile.c_str(),"r");

	if(bio != NULL)
	{
		globaldh = PEM_read_bio_DHparams(bio,NULL,NULL,NULL);
		BIO_free(bio);
		SSL_CTX_set_tmp_dh_callback(serverctx, tmp_dh_cb);		
	}
	else
	{
		return 0;
	}


#if OPENSSL_VERSION_NUMBER >= 0x10002000L
            /* OpenSSL >= 1.0.2 automatically handles ECDH temporary key parameter
               selection. */
            SSL_CTX_set_ecdh_auto(serverctx, 1);
#else
        {
            EC_KEY *ecdh = NULL;
            ecdh = EC_KEY_new_by_curve_name(NID_secp521r1);
            if (ecdh == NULL) {
                return 0;
            }
            SSL_CTX_set_tmp_ecdh(serverctx, ecdh);
            EC_KEY_free(ecdh);
        }	
#endif

	if (!SSL_CTX_check_private_key(serverctx))
	{		
		return 0;
	}	

	return 1;
}

SSL_CTX *BaseSock::getctx(void)
{
	return serverctx;
}

int BaseSock::SslAccept(string cipher)
{
	ssl = SSL_new(serverctx);
	if (ssl == NULL)
	{	
		return 0;
	}
	if(cipher != "")
	{
		SSL_set_cipher_list(ssl,cipher.c_str());
	}
	if (SSL_set_fd(ssl,sock) == 0)
	{	
		return 0;
	}
	
	SSL_set_verify(ssl,SSL_VERIFY_PEER,verify_callback);
		
	for(int i=0; i <200;i++)
	{
		int err = SSL_accept(ssl);
		if(err == 1)
		{
			break;
		}
		else
		{
			int sslerr = SSL_get_error(ssl, err);
			
			if( sslerr == SSL_ERROR_WANT_READ || sslerr == SSL_ERROR_WANT_WRITE || sslerr == SSL_ERROR_WANT_X509_LOOKUP)
			{
				if (shouldquit() == 1) 
				{	
					return 0;
				}
				Wait(50);
			}
			else
			{
				return 0;
			}
						
		}
		
	}	
	
	return 1;	
}

int BaseSock::SslConnect(string cipher)
{
	ssl = SSL_new(clientctx);
	if (ssl == NULL)
	{			
		return 0;
	}
	if(cipher != "")
	{
		SSL_set_cipher_list(ssl,cipher.c_str());
	}
	
	if(SSL_set_fd(ssl,sock) == 0)
	{			
		return 0;
	}
	//SSL_set_verify(ssl,SSL_VERIFY_PEER,verify_callback);
	
	// try for 10 seconds
	for(int i=0; i <200;i++)
	{
		int err = SSL_connect(ssl);
		if(err == 1)
		{
			break;
		}
		else
		{
			int sslerr = SSL_get_error(ssl, err);
			if( sslerr == SSL_ERROR_WANT_READ || sslerr == SSL_ERROR_WANT_WRITE || sslerr == SSL_ERROR_WANT_X509_LOOKUP)
			{
				if (shouldquit() == 1) 
				{						
					return 0;
				}
				Wait(50);
			}
			else
			{				
				return 0;
			}
		}
		
	}
		
	return 1;
}

int BaseSock::BlockWrite(char *data,int nrbytes)
{
	// no select - using blocking sockets
	int total = 0;
	int bytesleft = nrbytes;
	int rc;
	int count = 0;
	
	while(total < nrbytes)
	{
		if(ssl == NULL)
		{		
			rc = send(sock,data+total,bytesleft,0);
		}
		else
		{
			rc = SSL_write(ssl,data+total,bytesleft);
		}
		if(rc > 0)
		{
			count = 0;
			total += rc;
			bytesleft -= rc;
		}
		else if (rc == 0)
		{
			if(ssl != NULL) SSL_get_error(ssl,rc); // clear ssl error queue
			return 0;
		}
		else
		{
			if(count == retrycount()) { return 0; } // not more then x retries
			if (ssl != NULL)
			{
				int err = SSL_get_error(ssl,rc);
				
				if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_X509_LOOKUP) 
				{
					Wait(__delay);
					count++;
					continue;
				}
				else
				{							
					return 0;
				}
			}
			else
			{
#ifdef _WIN32
				int err = WSAGetLastError();
#else
				int err = errno;
#endif
				if(err == EAGAIN)
				{
					Wait(__delay);
					count++;
					continue;
				}
				else
				{
					return 0;
				}
			}
		}
	}
	return 1;
}

int BaseSock::BlockRead(char *buffer, int &nrbytes)
{
	int count = 0;
	while(1)
	{
			int rc;		
			if (ssl == NULL)
			{
				rc = recv(sock,buffer,buffersize(),0);
			}
			else
			{
				rc = SSL_read(ssl,buffer,buffersize());
			}
	  				
			if (rc > 0) 
			{ 
				count = 0;
				nrbytes = rc; 
				return 1; 
			}
			else  if(rc == 0)
			{
				if(ssl != NULL) SSL_get_error(ssl,rc); // clear ssl error queue
				nrbytes=0; 
				return 0; 
			}
			else
			{	
				if(count == retrycount()) { return 0; } // not more then x retries
				if (ssl != NULL)
				{
					int err = SSL_get_error(ssl,rc);
					
					if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_X509_LOOKUP) 
					{
						Wait(__delay);
						count++;
						continue;
					}
					else
					{
						return 0;
					}
					
				}
				else
				{
#ifdef _WIN32
					int err = WSAGetLastError();
#else
					int err = errno;
#endif
					if(err == EAGAIN)
					{
						Wait(__delay);
						count++;
						continue;
					}
					else
					{
						return 0;
					}
				}
								
				nrbytes=0; 
				return 0; 
			}
		}  	
		
	return 0;
}
