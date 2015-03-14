#include "config.h"

Config::Config()
{
	buffer = NULL;
	data = "";
}



int Config::Init(std::string filename, std::string blowkey)
{
	std::streamoff size = 0;
	if(!filesize(filename,size))
	{
		return 0;
	}
	readfile(filename,&buffer,(int)size);
	unsigned char *bufferout;
	if(blowkey != "")
	{
		bufferout = new unsigned char [size+1];		
		memset(bufferout,'\0',size+1);
		if(!decrypt(blowkey,buffer,bufferout,size))
		{
			delete [] bufferout;
			delete [] buffer;
			return 0;
		}
		data = (char*)bufferout;
		delete [] bufferout;
	}
	else
	{
		data = (char*)buffer;
	}
	delete [] buffer;	
	return 1;
}

int Config::GetString(std::string name, std::string &result)
{
	vector<string> res;
	split(res,data,'\n',false);
	if(res.size() == 0) return 0;
	for(int i=0; i < (int)res.size();i++)
	{
		res[i] = trim(res[i]);
	}
	bool found = false;
	for(int i=0; i < (int)res.size();i++)
	{
		if(res[i].length() > 0 && res[i][0] == '#') continue;
		if(res[i].find(name,0) != string::npos)
		{
			vector<string> tmp;
			split(tmp,res[i],'=',false);
			if(tmp.size() >= 2)
			{				
				vector<string> tmp2;
				split(tmp2,tmp[1],';',true);
				if(tmp2.size() >= 1)
				{
					found = true;
					result = tmp2[0];
					break;
				}				
			}
		}
	}
	if(found) return 1;
	else return 0;
}

int Config::GetInt(std::string name, int &result)
{
	vector<string> res;
	split(res,data,'\n',false);
	if(res.size() == 0) return 0;
	for(int i=0; i < (int)res.size();i++)
	{
		res[i] = trim(res[i]);
	}
	bool found = false;
	for(int i=0; i < (int)res.size();i++)
	{
		if(res[i].length() > 0 && res[i][0] == '#') continue;
		if(res[i].find(name,0) != string::npos)
		{
			vector<string> tmp;
			split(tmp,res[i],'=',false);
			if(tmp.size() >= 2)
			{
				
				vector<string> tmp2;
				split(tmp2,tmp[1],';',false);
				if(tmp2.size() >= 1)
				{
					found = true;
					result = atoi(tmp2[0].c_str());
					break;
				}				
			}
		}
	}
	if(found) return 1;
	else return 0;
}
