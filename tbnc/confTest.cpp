#include "global.h"
#include "serversock.h"
#include "entrythread.h"
#include "options.h"

Options options;


int main(int argc,char *argv[])
{
	if(!BaseSock::BaseInit())
	{
		cout << "base init failed\n";
		return 0;
	}

	int arganz = 0;
	string arg1 = "";
	string arg2 = "";

	arganz = argc -1;
	if(arganz > 0) arg1 = argv[1];
	if(arganz > 1) arg2 = argv[2];
	
	if(arganz < 1 && arganz > 2)
	{
		cout << "usage: confTest <configfile> or confTest -u <configfile> for uncrypted conf\n";
		return 0;
	}
	
	if(arganz == 1)
	{
		string key;
		getpassword("Enter blowfish key",key);
		if(!options.config.Init(arg1,key))
		{
			cout << "error reading conf\n";
			return 0;
		}
	}
	else
	{
		if(arg1 == "-u")
		{
			if(!options.config.Init(arg2,""))
			{
				cout << "error reading conf\n";
				return 0;
			}
		}
		else
		{
			cout << "usage: tbnc <configfile> or tbnc -u <configfile> for uncrypted conf\n";
			return 0;
		}
	}
	
	options.GetOptional();
	if(!options.GetRequired())
	{
		cout << "one or more basic options not set\n";
		return 0;
	}

	if(options.buffersize > 0)
	{
		BaseSock::Buffersize(options.buffersize);
	}

	if(options.sndrcvbufsize > 0)
	{
		BaseSock::SndRcvBufSize(options.sndrcvbufsize);
	}

	if(!BaseSock::BaseSslInit(options.certpath, options.certpath))
	{
		cout << "Ssl server init failed\n";
		return 0;
	}

	if(options.delay > 0)
	{
		BaseSock::Delay(options.delay);
	}

	if(options.retrycount > 0)
	{
		BaseSock::Retrycount(options.retrycount);
	}

	ServerSock ss;
	if(!ss.Init())
	{
		cout << "listen socket init failed\n";
		return 0;
	}
	
	cout << "starting site connect test\n";

	ClientSock sitesock;
	if(!sitesock.Init())
	{
		cout << "sitesock init failed\n";
		return 0;
	}
	if(options.connectip != "")
	{
		cout << "connect ip: " << options.connectip << "\n";
		if(!sitesock.Bind(options.connectip,0))
		{
			cout << "sitesock bind failed\n";
			return 0;
		}
	}
	if(!sitesock.Connect(options.siteip,options.siteport))
	{
		cout << "connect failed\n";
		return 0;
	}

	fd_set readfds;
	fd_set errorfds;

	FD_ZERO(&readfds);
	FD_ZERO(&errorfds);
	FD_SET(sitesock.sock, &readfds);
	FD_SET(sitesock.sock, &errorfds);

	if (select(sitesock.sock+1, &readfds, NULL, &errorfds, NULL) <= 0)
	{
		cout << "select error\n";
	}
	if(FD_ISSET(sitesock.sock, &errorfds))
	{
		cout << "error fds set\n";
	}

	string sitereply;
	if(!sitesock.ReadLine(sitereply))
	{
		cout << "read failed\n";
		return 0;
	}
	cout << "reply: " + sitereply;
	sitesock.Close();

	cout << "starting listen test\n";

	if(!ss.Bind(options.listenip, options.listenport))
	{
		cout << "could not bind\n";
		return 0;
	}

	ClientSock clientsock;
	if(!clientsock.Init())
	{
		cout << "clientsock init failed\n";
		return 0;
	}
	ss.Listen(100);
	string ip;
	int port;
	ss.Accept(clientsock, ip, port);
	cout << "connect from " << ip << " @ port " << port << "\n";
	clientsock.WriteLine("hello\r\n");
	clientsock.Close();
	ss.Close();

}