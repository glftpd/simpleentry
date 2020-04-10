#include "pasvthread.h"

PasvTrafficThread::PasvTrafficThread(Options *options, string siteip, int siteport)
{
	this->options = options;
	this->siteip = siteip;
	this->siteport = siteport;
}

bool PasvTrafficThread::InitListen(int listenPort)
{
	if(!listensock.Init()) return false;
	if(!listensock.Bind(options->listenip,listenPort)) return false;
	if(!listensock.Listen(100)) return false;
	return true;
}

bool PasvTrafficThread::InitSite()
{
	if(!sitesock.Init()) return false;
	if(options->connectip != "")
	{			
		if(!sitesock.Bind(options->connectip,0)) return false;
	}
	string tmp = siteip;
	if(options->ipfordata)
	{
		tmp = options->siteip;
	}
	if(!sitesock.Connect(tmp, siteport)) return false;
	
	return true;
}

void PasvTrafficThread::loop(void)
{
	if(!InitSite()) return;
	string ip;
	int port;
	if(!clientsock.Init(false)) return;
	if(!listensock.Accept(clientsock,ip,port,listensock.connecttimeout())) return;
	
	//sitesock.FastReadLoop(clientsock);
	sitesock.ReadLoop(clientsock);
	
	clientsock.Close();
	sitesock.Close();
	listensock.Close();
}

PasvTrafficThread::~PasvTrafficThread(void)
{
	listensock.Close();
	clientsock.Close();
	sitesock.Close();
}
