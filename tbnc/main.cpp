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

	cout << "Simple Win32/Linux traffic bouncer v0.2.1 2010/08/10 (c) _hawk_/PPX\n";
	cout << "Using " << version << "\n";
	
	if(arganz < 1 && arganz > 2)
	{
		cout << "usage: tbnc <configfile> or tbnc -u <configfile> for uncrypted conf\n";
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
		cout << "socket init failed\n";
		return 0;
	}
	if(!ss.Bind(options.listenip, options.listenport))
	{
		cout << "could not bind\n";
		return 0;
	}
	ss.Listen(100);
#ifdef _WIN32
	cout << "Close console window now - entry running in background now\n";
#endif
	daemon(1,1);

#ifdef _WIN32
#else
	if(options.pidfile != "")
	{
		int pid = getpid();
		
		ofstream pidf(options.pidfile.c_str(), ios::out | ios::trunc);
		if (!pidf)
		{
			cout << "can not create pid file\n";			
		}
		else
		{		
			pidf << pid << "\n";
			pidf.close();
		}
	}
#endif

	while(1)
	{
		EntryThread *et = NULL;
		et = new EntryThread(options);
		if(et != NULL)
		{
			if(et->cs.Init(false))
			{
				if(ss.Accept(et->cs,et->clientip,et->clientport))
				{	
					et->start(et);
				}
				else
				{
					delete et;
				}
			}
			else
			{
				delete et;
			}
		}
	}
	return 1;
}
