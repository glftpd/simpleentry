#include "global.h"
#include "basesock.h"
#include "clientsock.h"
#include "serversock.h"
#include "thread.h"
#include "config.h"

// config
string siteip = "";
int siteport = 0;
int idntcmd = 1;
int idnt = 1;
int listenport = 0;
string listenip = "";
string connectip = "";
int buffersize = 0;
string pidfile = "";
int sndrcvbufsize = 0;
int delay = 5;
int retrycount = 15;

class EntryThread: public Thread
{
public:
	ClientSock cs;
	ClientSock sitesock;
	string clientip;
	int clientport;

	void loop(void)
	{
		if(!sitesock.Init()) return;
		if(connectip != "")
		{			
			if(!sitesock.Bind(connectip,0)) return;
		}		
		string ident = "*";
		if(idnt)
		{
			cs.Ident(clientip,listenport,clientport,3,ident,listenip);
		}		
		if(!sitesock.Connect(siteip,siteport))
		{
			return;
		}
		if(idntcmd)
		{			
			stringstream ss;
			ss << "IDNT " << ident << "@" << clientip << ":" << clientip << "\r\n";			
			sitesock.WriteLine(ss.str());
		}
		cs.ReadLoop(sitesock);		
		sitesock.Close();		
		cs.Close();		
	}

	~EntryThread()
	{		
		cs.Close();
		sitesock.Close();		
	}
};

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

	cout << "Simple Win32/Linux entry bouncer v0.4.0 2009/09/23 (c) _hawk_/PPX\n";
	cout << "Using " << version << "\n";
	
	if(arganz < 1 && arganz > 2)
	{
		cout << "usage: entry <configfile> or entry -u <configfile> for uncrypted conf\n";
		return 0;
	}
	Config config;
	if(arganz == 1)
	{
		string key;
		getpassword("Enter blowfish key",key);
		if(!config.Init(arg1,key))
		{
			cout << "error reading conf\n";
			return 0;
		}
	}
	else
	{
		if(arg1 == "-u")
		{
			if(!config.Init(arg2,""))
			{
				cout << "error reading conf\n";
				return 0;
			}
		}
		else
		{
			cout << "usage: entry <configfile> or entry -u <configfile> for uncrypted conf\n";
			return 0;
		}
	}
	
	// optional options
	config.GetInt("idnt_command",idntcmd);
	config.GetInt("idnt_request",idnt);	
	config.GetString("connect_ip",connectip);
	config.GetString("listen_ip",listenip);
	config.GetInt("buffersize",buffersize);
	config.GetString("pidfile",pidfile);
	config.GetInt("sndrcvbufsize",sndrcvbufsize);
	config.GetInt("delay",delay);
	config.GetInt("retrycount",retrycount);

	// required options
	bool found = true;
	if(!config.GetString("site_ip",siteip)) found = false;
	if(!config.GetInt("site_port",siteport)) found = false;
	if(!config.GetInt("listen_port",listenport)) found = false;

	if(!found)
	{
		cout << "one or more basic options not set\n";
		return 0;
	}

	if(buffersize > 0)
	{
		BaseSock::Buffersize(buffersize);
	}

	if(sndrcvbufsize > 0)
	{
		BaseSock::SndRcvBufSize(sndrcvbufsize);
	}

	if(delay > 0)
	{
		BaseSock::Delay(delay);
	}

	if(retrycount > 0)
	{
		BaseSock::Retrycount(retrycount);
	}

	ServerSock ss;
	if(!ss.Init())
	{
		cout << "socket init failed\n";
		return 0;
	}
	if(!ss.Bind(listenip,listenport))
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
	if(pidfile != "")
	{
		int pid = getpid();
		
		ofstream pidf(pidfile.c_str(), ios::out | ios::trunc);
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
		EntryThread *tt = NULL;
		tt = new EntryThread;
		if( tt != NULL)
		{
			if(tt->cs.Init(false))
			{
				if(ss.Accept(tt->cs,tt->clientip,tt->clientport))
				{	
					tt->start(tt);
				}
				else
				{
					delete tt;
				}
			}
			else
			{
				delete tt;
			}
		}
	}
	return 1;
}
