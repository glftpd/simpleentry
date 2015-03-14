#ifndef CONFIG_H
#define CONFIG_H

#include "global.h"
#include "strings.h"

class DLL Config
{
public:
	int Init(string filename, string blowkey);
	Config();
	int GetString(string name, string &result);
	int GetInt(string name, int &result);
	int GetDouble(string name, double &result);

protected:
	
	unsigned char *buffer ;
	string data;
};

#endif
