#include "global.h"
#include "basesock.h"
#include "clientsock.h"
#include "serversock.h"
#include "thread.h"
#include "config.h"

// config
string username = "";
string userpass = "";
int allownopass = 0;
int usessl = 0;
int listenport = 0;
string listenip = "";
string connectip = "";
int bindstart = 40000;
int bindend = 45000;
string iprange = "";
string certpath = "";
int buffersize = 0;
string pidfile = "";
int sndrcvbufsize = 0;
int delay = 5;
int retrycount = 15;

int IpCheck(string clientip)
{
	if(iprange == "") return 1;
	vector<string> ips;
	split(ips,iprange,',',false);
	if(ips.size() == 0) return 1;
	int matches = 0;
	for(unsigned int i=0; i < ips.size();i++)
	{
		if(MatchIp(ips[i],clientip)) matches = 1;
	}
	return matches;
}

class SocksThread: public Thread
{
public:
	ClientSock cs;
	ClientSock sitesock;
	ServerSock ss;
	string clientip;
	int clientport;

	void SendError(int b1, int b2)
	{
		cs.buffer[0] = b1;
		cs.buffer[1] = b2;
		cs.Write(cs.buffer, 2);
	}

	void loop(void)
	{
		if(usessl)
		{
			if(!cs.SslAccept(""))
			{
				return;
			}
		}
		int bytesread = 0;
		if(!cs.Read(cs.buffer, bytesread))
		{
			return;
		}
		if(bytesread < 3 || bytesread > 257)
		{
			return;
		}
		// ip range check
		if(!IpCheck(clientip))
		{
			SendError(5,255);
			return;
		}

		// protocol version
		if(cs.buffer[0] != 5)
		{
			SendError(5,255);
			return;
		}
		// number of methods
		if(cs.buffer[1] < 1)
		{
			SendError(5,255);
			return;
		}
		// number of methods matches bytesread?
		if(cs.buffer[1] + 2 != bytesread)
		{
			SendError(5,255);
			return;
		}
		// user/pass method?
		bool right_method = false;
		bool no_pass = false;
		for(int i=0;i < cs.buffer[1];i++)
		{
			if(cs.buffer[i+2] == 2) right_method = true;
			if(cs.buffer[i+2] == 0) no_pass = true;
		}
		if(right_method || (no_pass && allownopass))
		{
			
		}
		else
		{
			SendError(5,255);
			return;
		}

		// send reply
		cs.buffer[0] = 5; // protocol version
		cs.buffer[1] = 2; // method user/pass

		if(no_pass && allownopass) cs.buffer[1] = 0;
		if(!cs.Write(cs.buffer,2))
		{
			return;
		}

		// check user & pass
		if(!(no_pass && allownopass))
		{
			if(!cs.Read(cs.buffer, bytesread))
			{
				return;
			}
			if(bytesread < 4)
			{
				SendError(1,1);
				return;
			}

			// get name & pass
			int namel,passl;
			namel = 0;
			passl = 0;

			if(cs.buffer[0] != 1)
			{
				SendError(1,1);
				return;				
			}
			
			namel = cs.buffer[1];
			string name;
			if(namel + 2 >= bytesread)
			{
				SendError(1,1);
				return;
			}
			for(int i=0;i < namel;i++)
			{
				name += cs.buffer[i+2];
			}
			passl = cs.buffer[2+namel];
			if(namel + 3 + passl > bytesread)
			{
				SendError(1,1);
				return;
			}
			string pass;
			for(int i=0;i < passl;i++)
			{
				pass += cs.buffer[i+3+namel];
			}
			

			if(name != username || pass != userpass)
			{
				SendError(1,1);
				return;
			}

			// send reply
			cs.buffer[0] = 1;
			cs.buffer[1] = 0;
			if(!cs.Write(cs.buffer,2))
			{
				return;
			}
		}

		if(!cs.Read(cs.buffer, bytesread))
		{
			return;
		}

		if(bytesread < 10)
		{
			SendError(5,1);
			return;
		}
		if(cs.buffer[0] != 5)
		{
			SendError(5,1);
			return;
		}

		// get connect method
		string method = "";
		if(cs.buffer[1] == 1)
		{
			method = "connect";
		}
		else if(cs.buffer[1] == 2)
		{
			method = "bind";
		}
		else
		{
			SendError(5,1);
			return;
		}

		if(cs.buffer[2] != 0)
		{
			SendError(5,1);
			return;
		}

		if(cs.buffer[3] == 1)
		{
			// ipv4
		}
		else if(cs.buffer[3] == 3)
		{
			// domain name
		}
		else
		{
			SendError(5,1);
			return;
		}

		if(method == "connect")
		{			
			string ip;
			struct sockaddr_in myaddr;
			myaddr.sin_family = AF_INET;
			if(cs.buffer[3] == 1)
			{
				memcpy(&myaddr.sin_addr.s_addr,cs.buffer+4,4);
				ip = inet_ntoa(myaddr.sin_addr);
				memcpy(&myaddr.sin_port, cs.buffer+8,2);
			}
			else if(cs.buffer[3] == 3)
			{
				// first check if length is ok
				if(bytesread < cs.buffer[4] + 6)
				{
					SendError(5,1);
					return;
				}
				memcpy(&myaddr.sin_port,cs.buffer + cs.buffer[4] + 5,2);
				for(int i=0; i < cs.buffer[4];i++)
				{
					ip += (char)cs.buffer[5+i];								
				}
			}			
			myaddr.sin_port = ntohs(myaddr.sin_port);
			if(!sitesock.Init())
			{
				SendError(5,1);
				return;
			}
			if(connectip != "")
			{			
				if(!sitesock.Bind(connectip,0))
				{
					SendError(5,1);
					return;
				}
			}
			if(!sitesock.Connect(ip,myaddr.sin_port))
			{
				SendError(5,5);
				return;
			}
			
			// try to get platform independent function to get own ip
			string ownip = "0.0.0.0";
			if(listenip != "") ownip = listenip;
			struct sockaddr_in listenadr;
			listenadr = cs.GetIp(ownip,listenport);
			cs.buffer[0] = 5; // protocol version
			cs.buffer[1] = 0; // succeeded
			cs.buffer[2] = 0;
			cs.buffer[3] = 1;
			
			memcpy(cs.buffer+8,&listenadr.sin_port,2);
			memcpy(cs.buffer+4,&listenadr.sin_addr,4);
			if(!cs.Write(cs.buffer,10))
			{
				return;
			}			
		}
		else if (method == "bind")
		{			
			if(!sitesock.Init())
			{
				SendError(5,1);
				return;
			}

			if(!ss.Init())
			{
				SendError(5,5);
				return;
			}

			// pick a random listen port
			int bindport = random_range(bindstart, bindend);
			if(!ss.Bind(listenip, bindport))
			{
				SendError(5,5);
				return;
			}
			if(!ss.Listen(3))
			{
				SendError(5,5);
				return;
			}
			// try to get platform independent function to get own ip
			string ownip = "0.0.0.0";
			if(listenip != "") ownip = listenip;
			struct sockaddr_in listenadr;
			listenadr = cs.GetIp(ownip,bindport);
			cs.buffer[0] = 5; // protocol version
			cs.buffer[1] = 0; // succeeded
			cs.buffer[2] = 0;
			cs.buffer[3] = 1;
			
			memcpy(cs.buffer+8,&listenadr.sin_port,2);
			memcpy(cs.buffer+4,&listenadr.sin_addr,4);
			if(!cs.Write(cs.buffer,10))
			{
				return;
			}
			string cip;
			int cport;
			if(!ss.Accept(sitesock, cip, cport))
			{
				SendError(5,1);
				return;
			}

			if(!cs.Write(cs.buffer,10))
			{
				return;
			}

			ss.Close();
		}
		else
		{
			SendError(5,5);
			return;
		}
		
		cs.ReadLoop(sitesock);
		
		sitesock.Close();
		cs.Close();		
	}

	~SocksThread()
	{		
		cs.Close();
		sitesock.Close();
		ss.Close();
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

	cout << "Simple Win32/Linux socks5 proxy v0.2.1 2010/09/22 (c) _hawk_/PPX\n";
	cout << "Using " << version << "\n";
	
	if(arganz < 1 && arganz > 2)
	{
		cout << "usage: simplesocks <configfile> or simplesocks -u <configfile> for uncrypted conf\n";
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
			cout << "usage: simplesocks <configfile> or simplesocks -u <configfile> for uncrypted conf\n";
			return 0;
		}
	}


	// optional options
	config.GetInt("allow_nopass",allownopass);
	config.GetInt("use_ssl",usessl);
	config.GetString("connect_ip",connectip);
	config.GetString("listen_ip",listenip);	
	config.GetInt("bindstart",bindstart);
	config.GetInt("bindend",bindend);
	config.GetString("iprange",iprange);
	config.GetString("cert_path",certpath);
	config.GetInt("buffersize",buffersize);
	config.GetString("pidfile",pidfile);
	config.GetInt("sndrcvbufsize",sndrcvbufsize);
	config.GetInt("delay",delay);
	config.GetInt("retrycount",retrycount);

	// required options
	bool found = true;
	if(!config.GetString("username",username)) found = false;
	if(!config.GetString("userpass",userpass)) found = false;	
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
	if(usessl)
	{
		if(!BaseSock::BaseSslInit(certpath,certpath))
		{
			cout << "Ssl server init failed\n";
			return 0;
		}
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
		SocksThread *st = NULL;
		st = new SocksThread;
		if(st != NULL)
		{	
			if(st->cs.Init(false))
			{
				if(ss.Accept(st->cs,st->clientip,st->clientport))
				{
					st->start(st);
				}
				else
				{
					delete st;
				}
			}
			else
			{
				delete st;
			}
		}
	}
	return 1;
}
