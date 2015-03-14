#include "portthread.h"

PortTrafficThread::PortTrafficThread(Options options, string siteip, int siteport)
{
	this->options = options;
	this->siteip = siteip;
	this->siteport = siteport;
}

bool PortTrafficThread::InitSite()
{
	if(!sitesock.Init()) return false;
	if(options.connectip != "")
	{			
		if(!sitesock.Bind(options.connectip,0)) return false;
	}
	string tmp = siteip;
	if(options.ipfordata)
	{
		tmp = options.siteip;
	}
	if(!sitesock.Connect(tmp, siteport)) return false;
	
	return true;
}

bool PortTrafficThread::InitPort(string activeip,  int activeport)
{
	this->activeip = activeip;
	this->activeport = activeport;
	if(!clientsock.Init()) return false;
	if(options.listenip != "")
	{			
		if(!clientsock.Bind(options.listenip,0)) return false;
	}
	if(!clientsock.Connect(activeip, activeport)) return false;
	return true;
}

void PortTrafficThread::loop(void)
{	
	if(!InitSite()) return;
	sitesock.ReadLoop(clientsock);
	sitesock.Close();
	clientsock.Close();
}

PortTrafficThread::~PortTrafficThread()
{	
	clientsock.Close();
	sitesock.Close();
}