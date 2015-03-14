#include "entrythread.h"

EntryThread::EntryThread(Options *options)
{
	this->options = options;
	id = "-1";
}

// check reply for siteip - should never reach user
bool EntryThread::checkReply(string reply)
{
	if(reply.find(options->siteip) != string::npos) return false;
	string tmp = options->siteip;
	int pos = tmp.find(".");
	while(pos != string::npos)
	{
		tmp = tmp.replace(pos,1,",");
		pos = tmp.find(".",pos + 1);
	}
	if(reply.find(tmp) != string::npos) return false;
	return true;
}

// do ssl handshake
bool EntryThread::doSsl(int type)
{
	string reply;

	if(type == 0)
	{
		if(!sitesock.WriteLine("AUTH SSL\r\n"))
		{
			return false;
		}
	}
	else if(type == 1)
	{
		if(!sitesock.WriteLine("AUTH TLS\r\n"))
		{
			return false;
		}
	}

	if(!sitesock.ReadLine(reply))
	{
		return false;
	}
	int code = ftpCode(reply);
	if(code != 234)
	{
		return false;
	}
	
	if(!sitesock.SslConnect(""))
	{
		return false;
	}
	if(type == 0)
	{
		if(!cs.WriteLine("234 AUTH SSL successful\r\n"))
		{
			return false;
		}
	}
	else if(type == 1)
	{
		if(!cs.WriteLine("234 AUTH TLS successful\r\n"))
		{
			return false;
		}
	}

	if(!cs.SslAccept(""))
	{
		return false;
	}
	return true;
}

// handle site replies
bool EntryThread::doSite()
{
	string sitereply;
	if(!sitesock.ReadLine(sitereply))
	{
		return false;
	}
	options->Log(id + "from site: " + sitereply);
	if(options->checkForIp)
	{
		if(!checkReply(sitereply))
		{
			return false;
		}
	}	
	if(!cs.WriteLine(sitereply))
	{
		return false;
	}
	return true;
}

// handle user commands
bool EntryThread::doUser()
{
	string userreply;
	if(!cs.ReadLine(userreply))
	{
		return false;
	}
	options->Log(id + "from user: " + userreply);
	if(StartsWith(toupper(userreply), "IDNT"))
	{
		if(options->entries.size() == 0)
		{
			return false;
		}
		else
		{
			if(!sitesock.WriteLine(userreply))
			{
				return false;
			}
		}
	}
	if(StartsWith(toupper(userreply), "AUTH SSL"))
	{
		if(!doSsl(0)) return false;
	}
	else if(StartsWith(toupper(userreply), "AUTH TLS"))
	{
		if(!doSsl(1)) return false;
	}
	else if(StartsWith(toupper(userreply), "PASV"))
	{
		if(!doPasv()) return false;
	}
	else if(StartsWith(toupper(userreply), "CPSV"))
	{
		if(!doCpsv()) return false;
	}
	else if(StartsWith(toupper(userreply), "PORT "))
	{
		if(!doPort(userreply)) return false;
	}
	else
	{				
		if(!sitesock.WriteLine(userreply))
		{
			return false;
		}
	}
	return true;
}

// handle PASV command
bool EntryThread::doPasv()
{
	string reply;
	bool error = false;

	if(!sitesock.WriteLine("PASV\r\n"))
	{
		error = true;
	}
	else
	{
		if(!sitesock.ReadLine(reply))
		{
			error = true;
		}
		else
		{
			int code = ftpCode(reply);
			if(code != 227)
			{
				error = true;
			}
		}
	}

	if(error)
	{
		if(!cs.WriteLine("425 Can't open data connection.\r\n"))
		{
			return false;
		}
		return true;
	}
	
	string ip;
	int port;
	if(!parsePasvCmd(reply,ip,port)) return false;
	
	PasvTrafficThread *ptt = new PasvTrafficThread(options, ip, port);
	if(ptt == NULL) return false;

	int listenPort = port + options->addtopasvport;

	if(!ptt->InitListen(listenPort))
	{
		delete ptt;
		if(!cs.WriteLine("425 Can't open data connection.\r\n"))
		{
			return false;
		}
	}
	else
	{		
		vector<string> tmpIp;
		if(options->listenip != "")
		{
			split(tmpIp,options->listenip,'.',false);
		}
		else if(options->natpasvip != "")
		{
			split(tmpIp, cs.GetIpStr(options->natpasvip),'.',false);
		}
		else
		{
			split(tmpIp,"127.0.0.1",'.',false);
		}
		if(tmpIp.size() != 4)
		{
			delete ptt;
			return false;
		}
		
		if(!cs.WriteLine("227 Entering Passive Mode (" + tmpIp[0] + "," + tmpIp[1] + "," + tmpIp[2] + "," + tmpIp[3] +"," + int2str(listenPort / 256) + "," + int2str(listenPort % 256) + ")\r\n"))
		{
			delete ptt;
			return false;
		}
		ptt->start(ptt);
	}		
	return true;
}

// handle CPSV command
bool EntryThread::doCpsv()
{
	string reply;
	bool error = false;

	if(!sitesock.WriteLine("CPSV\r\n"))
	{
		error = true;
	}
	else
	{
		if(!sitesock.ReadLine(reply))
		{
			error = true;
		}
		else
		{
			int code = ftpCode(reply);
			if(code != 227)
			{
				error = true;
			}
		}
	}

	if(error)
	{
		if(!cs.WriteLine("425 Can't open data connection.\r\n"))
		{
			return false;
		}
		return true;
	}
	
	string ip;
	int port;
	if(!parsePasvCmd(reply,ip,port)) return false;
	
	PasvTrafficThread *ptt = new PasvTrafficThread(options, ip, port);
	if(ptt == NULL) return false;

	int listenPort = port + options->addtopasvport;

	if(!ptt->InitListen(listenPort))
	{
		delete ptt;
		if(!cs.WriteLine("425 Can't open data connection.\r\n"))
		{
			return false;
		}
	}
	else
	{		
		vector<string> tmpIp;
		if(options->listenip != "")
		{
			split(tmpIp,options->listenip,'.',false);
		}
		else
		{
			split(tmpIp,"127.0.0.1",'.',false);
		}
		if(tmpIp.size() != 4)
		{
			delete ptt;
			return false;
		}
		
		if(!cs.WriteLine("227 Entering Passive Mode (" + tmpIp[0] + "," + tmpIp[1] + "," + tmpIp[2] + "," + tmpIp[3] +"," + int2str(listenPort / 256) + "," + int2str(listenPort % 256) + ")\r\n"))
		{
			delete ptt;
			return false;
		}
		ptt->start(ptt);
	}		
	return true;
}

// handle PORT command
bool EntryThread::doPort(string portCmd)
{
	string reply;
	bool error = false;

	if(!sitesock.WriteLine("PASV\r\n"))
	{
		error = true;
	}
	else
	{
		if(!sitesock.ReadLine(reply))
		{
			error = true;
		}
		else
		{
			int code = ftpCode(reply);
			if(code != 227)
			{
				error = true;
			}
		}
	}
	
	if(error)
	{
		if(!cs.WriteLine("425 Can't open data connection.\r\n"))
		{
			return false;
		}
		return true;
	}

	string ip;
	int port;
	if(!parsePasvCmd(reply,ip,port)) return false;
	
	string activeip;
	int activeport;
	if(!parsePortCmd(portCmd,activeip,activeport)) return false;

	PortTrafficThread *ptt = new PortTrafficThread(options, ip, port);
	if(ptt == NULL) return false;
	if(!ptt->InitPort(activeip, activeport))
	{
		delete ptt;
		if(!cs.WriteLine("425 Can't open data connection.\r\n"))
		{
			return false;
		}
	}
	else
	{		
		if(!cs.WriteLine("200 PORT command successful.\r\n"))
		{
			delete ptt;
			return false;
		}
		ptt->start(ptt);
	}
	return true;
}

// main loop
void EntryThread::loop(void)
{
	stringstream ss;
	ss << cs.sock << ": ";
	id = ss.str();

	if(!sitesock.Init()) return;
	if(options->entrylist.size() > 0)
	{
		bool found = false;
		for(unsigned int i=0; i < options->entrylist.size();i++)
		{
			if(options->entrylist[i] == clientip)
			{
				found = true;
				break;
			}
		}
		if(!found) return;
	}
	if(options->connectip != "")
	{
		if(!sitesock.Bind(options->connectip,0)) return;
	}	
	if(!sitesock.Connect(options->siteip,options->siteport))
	{
		return;
	}
	if(options->entrylist.size() == 0)
	{
		string ident = "*";
		if(options->idnt)
		{
			cs.Ident(clientip,options->listenport,clientport,3,ident,options->listenip);
		}
		if(options->idntcmd)
		{
			stringstream ss;
			ss << "IDNT " << ident << "@" << clientip << ":" << clientip << "\r\n";
			sitesock.WriteLine(ss.str());
		}
	}

	fd_set readfds;
	fd_set errorfds;

	while(1)
	{
		FD_ZERO(&readfds);
		FD_ZERO(&errorfds);
		FD_SET(sitesock.sock, &readfds);
		FD_SET(cs.sock, &readfds);
		FD_SET(sitesock.sock, &errorfds);
		FD_SET(cs.sock, &errorfds);
		
		int tmpsock;
		if (sitesock.sock > cs.sock)
		{
			tmpsock = sitesock.sock;
		}
		else
		{
			tmpsock = cs.sock;
		}		
		
		if (select(tmpsock+1, &readfds, NULL, &errorfds, NULL) <= 0)
		{
			break;
		}
		if(FD_ISSET(sitesock.sock, &errorfds) || FD_ISSET(cs.sock, &errorfds))
		{	
			break;
		}

		// read from site
		if (FD_ISSET(sitesock.sock, &readfds))
		{	
			if(!doSite())
			{
				break;
			}
		}
		// read from user
		else if (FD_ISSET(cs.sock, &readfds))
		{
			if(!doUser())
			{
				break;
			}
		}
		else
		{
			break;
		}
	} // end while

	sitesock.Close();
	cs.Close();
}

EntryThread::~EntryThread(void)
{		
	cs.Close();
	sitesock.Close();
}