#ifndef OPTIONSTHREAD_H
#define OPTIONSTHREAD_H

#include "global.h"
#include "config.h"
#include "lock.h"

class Options
{
public:
	// config values go here
	string siteip;
	int siteport;
	int idntcmd;
	int idnt;
	int listenport;
	string listenip;
	string connectip;
	int buffersize;
	string pidfile;
	int sndrcvbufsize;
	string certpath;
	string entries;
	int ipfordata;
	int addtopasvport;
	int delay;
	int retrycount;
	string natpasvip;
	int checkForIp;
	string logFile;
	int logToScreen;
	// config end#

	// store entry ips here
	vector<string> entrylist;

	Options(void);

	void GetOptional(void);
	bool GetRequired(void);

	void Log(string msg);

	Config config;

private:
	Lock lock;
};


#endif
