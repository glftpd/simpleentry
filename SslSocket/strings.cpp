#include "strings.h"
#include <cstring>

string trim_right (const string & s, const string &t)
{
	string d (s);
	string::size_type i (d.find_last_not_of (t));
	if (i == string::npos)
	return "";
	else
	return d.erase (d.find_last_not_of (t) + 1) ;
}

string trim_left (const string & s, const string &t)
{
	string d (s);
	return d.erase (0, s.find_first_not_of (t)) ;
}

string trim (const string & s, const string &t)
{
	string d (s);
	return trim_left (trim_right (d, t), t) ;
}

// returns a lower case version of the string
string tolower (const string & s)
{
	string d (s);

	transform (d.begin (), d.end (), d.begin (), (int(*)(int)) tolower);
	return d;
}

// returns an upper case version of the string
string toupper (const string & s)
{
	string d (s);

	transform (d.begin (), d.end (), d.begin (), (int(*)(int)) toupper);
	return d;
}

int split(vector<string> &res, string str, char seperator, bool includeempty)
{
	res.clear();
    string::const_iterator start = str.begin();
    while (true)
	{
        string::const_iterator begin = start;

        while (start != str.end() && *start != seperator) { ++start; }

		if(string(begin,start).empty() && !includeempty)
		{
		}
		else
		{
			res.push_back(string(begin, start));
		}

		if (start == str.end())
		{
            break;
        }

        if (++start == str.end())
		{
			if(includeempty)
			{
				res.push_back("");
			}
            break;
        }
    }
    return res.size();
}

int filesize(string filename,std::streamoff &s)
{
	ifstream ifile(filename.c_str(),ios::binary | ios::in);
	if (!ifile)
	{
		return 0;
	}
	std::streamoff start,end;
	start = ifile.tellg();
	ifile.seekg(0,ios::end);
	end = ifile.tellg();
	ifile.seekg(0,ios::beg);
	s = end-start;
	return 1;
}

int readfile(string filename,unsigned char **data,int s)
{
	ifstream ifile(filename.c_str(),ios::binary | ios::in);
	*data = new unsigned char [s+1];
	ifile.read((char *)*data,s);
	ifile.close();
	data[0][s] = '\0';
	return 1;
}

int writefile(string filename,unsigned char *data,int s)
{
	ofstream ofile(filename.c_str(),ios::binary | ios::out | ios::trunc);
	if (!ofile)
	{
		return 0;
	}
	ofile.write((char*)data,s);
	ofile.close();
	return 1;
}

int decrypt(string key,unsigned char *datain,unsigned char *dataout,int s)
{
	unsigned char ivec[8];
	memset(ivec,0, 8);
	int ipos = 0;
	int outlen = s;

	EVP_CIPHER_CTX *pctx;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	EVP_CIPHER_CTX ctx;
	pctx = &ctx;
#else
	pctx = EVP_CIPHER_CTX_new();
#endif
	EVP_CIPHER_CTX_init(pctx);
    EVP_CipherInit_ex(pctx, EVP_bf_cfb(), NULL, NULL, NULL,ipos );
    EVP_CIPHER_CTX_set_key_length(pctx, key.length());
    EVP_CipherInit_ex(pctx, NULL, NULL,(unsigned char*)key.c_str(), ivec,ipos );

	if(!EVP_CipherUpdate(pctx, dataout, &outlen, datain, s))
	{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		EVP_CIPHER_CTX_free(pctx);
#endif
		return 0;
	}

	EVP_CIPHER_CTX_cleanup(pctx);
 	for (int i=0;i < (int)key.length();i++) { key[i] = '0'; }
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	EVP_CIPHER_CTX_free(pctx);
#endif
        return 1;
}

int encrypt(string key,unsigned char *datain,unsigned char *dataout,int s)
{
	unsigned char ivec[8];
	memset(ivec, 0,8);
	int outlen = s;

	EVP_CIPHER_CTX *pctx;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	EVP_CIPHER_CTX ctx;
	pctx = &ctx;
#else
	pctx = EVP_CIPHER_CTX_new();
#endif
	EVP_CIPHER_CTX_init(pctx);
        EVP_EncryptInit_ex(pctx, EVP_bf_cfb(), NULL, NULL, NULL );
        EVP_CIPHER_CTX_set_key_length(pctx, key.length());
        EVP_EncryptInit_ex(pctx, NULL, NULL, (unsigned char*)key.c_str(), ivec );

	if(!EVP_EncryptUpdate(pctx, dataout, &outlen, datain, s))
	{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		EVP_CIPHER_CTX_free(pctx);
#endif
		return 0;
	}

	EVP_CIPHER_CTX_cleanup(pctx);
 	for (int i=0;i < (int)key.length();i++) { key[i] = '0'; }
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	EVP_CIPHER_CTX_free(pctx);
#endif
        return 1;
}

int MatchIp(const string& ip1, const string& ip2)
{
	// einfachster fall
	if(ip1 == ip2) return 1;
	vector<string> vip1;
	vector<string> vip2;
	if(split(vip1,ip1,'.',false) != 4) return 0;
	if(split(vip2,ip2,'.',false) != 4) return 0;
	// alle 4 blöcke vergleichen
	for(int i=0; i < 4;i++)
	{
		string s1,s2;
		s1 = vip1[i];
		s2 = vip2[i];
		int pos = 0;
		int lpos = 0;
		int rpos = 0;

		// den längeren block raussuchen
		int max_size = 0;
		max_size = (int)s1.length();
		if((int)s2.length() > max_size) max_size = (int)s2.length();

		while(pos < max_size)
		{
			// stimmen die längen der laufvariablen noch?
			if(s1[lpos] == '*') break; // sonderfall *
			if(lpos >= (int)s1.length()) return 0;
			if(rpos >= (int)s2.length()) return 0;

			// bei ? kein vergleich - nur zähler erhöhen
			if(s1[lpos] == '?')
			{
				pos++;
				lpos++;
				rpos++;
			}
			// alles nach * ist ok (192.168.1.1*1 usinnig)
			else if(s1[lpos] == '*')
			{
				break;
			}
			// normalfall - beide stellen vergleichen
			else
			{
				if(s1[lpos] != s2[rpos]) return 0;
				lpos++;
				rpos++;
				pos++;
			}
		}
	}
	return 1;
}

void getpassword(string prompt, string &pass)
{
#ifdef _WIN32
	HANDLE hConsole = GetStdHandle(STD_INPUT_HANDLE);
    DWORD oldMode;
    if (!GetConsoleMode(hConsole, &oldMode))
	{
        return;
    }
    DWORD newMode = oldMode & ~ENABLE_ECHO_INPUT;
    if (!SetConsoleMode(hConsole, newMode))
	{
        return;
    }

	cout << prompt << ": ";
    cin >> pass;

    // restore console echo
    if (!SetConsoleMode(hConsole, oldMode))
	{
        return;
    }
	cout << "\n";
#else
	char *k;
	k = getpass((prompt + ": ").c_str());
	pass = k;
	memset(k, 0,pass.length());
#endif
}

int ftpCode(string reply)
{
	vector<string> res;
	if(split(res,reply,'\n',false) == 0) return 0;
	if(split(res,res[res.size() -1],' ',false) == 0) return 0;
	string tmp = res[0];
	if(tmp.length() > 1 && tmp[tmp.length() -1] == '-') tmp = tmp.substr(0,tmp.length() - 2);
	int code = atoi(tmp.c_str());
	return code;
}

bool parsePasvCmd(string cmd, string &ip, int &port)
{
	size_t pos1 = cmd.find("(");
	size_t pos2 = cmd.find(")",pos1);
	if(pos1 == string::npos || pos2 == string::npos) return false;
	string tmp = cmd.substr(pos1 + 1, pos2 - 2);
	vector<string> vec;
	if(split(vec,tmp,',',false) != 6) return false;

	ip = vec[0] + "." + vec[1] + "." + vec[2] + "." + vec[3];
	port = atoi(vec[4].c_str()) * 256 + atoi(vec[5].c_str());
	return true;
}

bool parseEpsvCmd(string cmd, string &ip, int &port) {
  int pos1 = cmd.find("(");
  int pos2 = cmd.find(")",pos1);
  if(pos1 == string::npos || pos2 == string::npos) return false;
  string tmp = cmd.substr(pos1 + 1, pos2 - 2);
  vector<string> vec;
  if(split(vec,tmp,'|',false) == 2) { //rfc response
   ip = "";
   port = atoi(vec[0].c_str());
   return true;
  }
  return false;
}

bool parsePortCmd(string cmd, string &ip, int &port)
{
	size_t pos1 = cmd.find(" ");
	size_t pos2 = cmd.length() -1;
	if(pos1 == string::npos || pos2 == string::npos) return false;
	string tmp = cmd.substr(pos1 + 1, pos2 - 2);
	vector<string> vec;
	if(split(vec,tmp,',',false) != 6) return false;

	ip = vec[0] + "." + vec[1] + "." + vec[2] + "." + vec[3];
	port = atoi(vec[4].c_str()) * 256 + atoi(vec[5].c_str());
	return true;
}

int random_range(int lowest_number, int highest_number)
{
  if(lowest_number > highest_number){
      swap(lowest_number, highest_number);
  }

  int range = highest_number - lowest_number + 1;
  double r = ((double)rand() / ((double)(RAND_MAX)+1) );
  return (lowest_number + abs(int(range * r)));
}

string int2str(int i)
{
	stringstream ss;
	ss << i;
	return ss.str();
}

bool StartsWith(string s, string v)
{
	size_t pos = s.find(v);
	if(pos == string::npos) return false;
	if(pos == 0) return true;
	else return false;
}

string replace(string input, string repl, string with)
{
	string tmp = input;
	size_t position = tmp.find(repl);

	while (position != string::npos)
	{
		tmp.replace(position, repl.length(), with);
		position = tmp.find(repl, position + with.length());
	}
	return tmp;
}
