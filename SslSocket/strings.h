#ifndef STRINGS_H
#define STRINGS_H

#include "global.h"

#define SPACES " \v\f\t\r\n"

DLL string trim_right (const string & s, const string & t = SPACES);
DLL string trim_left (const string & s, const string & t = SPACES);
DLL string trim (const string & s, const string & t = SPACES);
DLL string tolower (const string & s);
DLL string toupper (const string & s);
DLL int split(vector<string> &res, string s, char seperator, bool includeempty);
DLL int filesize(string filename,std::streamoff &s);
DLL int readfile(string filename,unsigned char **data,int s);
DLL int writefile(string filename,unsigned char *data,int s);
DLL int decrypt(string key,unsigned char *datain,unsigned char *dataout,int s);
DLL int encrypt(string key,unsigned char *datain,unsigned char *dataout,int s);
DLL void getpassword(string prompt, string &pass);
DLL int MatchIp(const string& ip1, const string& ip2);
DLL int ftpCode(string reply);
DLL bool parsePasvCmd(string cmd, string &ip, int &port);
DLL bool parseEpsvCmd(string cmd, string &ip, int &port);
DLL bool parsePortCmd(string cmd, string &ip, int &port);
DLL int random_range(int lowest_number, int highest_number);
DLL string int2str(int);
DLL string replace(string input, string repl, string with);
DLL bool StartsWith(string s, string v);
#endif
