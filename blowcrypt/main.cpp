#include "global.h"
#include "strings.h"


int main(int argc,char *argv[])
{
	cout << "Blowcrypt v0.4 2009/08/31 (c) _hawk_/PPX\n";
	cout << "Using " << version << "\n";
	
	if(argc != 4)
	{
		cout << "Usage: blowcrypt -d <infile> <outfile> to decrypt infile into outfile\n       blowcrypt -e <infile> <outfile> to encrypt infile into outfile\n";
		return 0;
	}
	else
	{
		string arg1 = argv[1];
		string arg2 = argv[2];
		string arg3 = argv[3];
		if(!(arg1 != "-d" || arg1 != "-e"))
		{
			cout << "Usage: blowcrypt -d <infile> <outfile> to decrypt infile into outfile\n       blowcrypt -e <infile> <outfile> to encrypt infile into outfile\n";
			return 0;
		}
		else if(arg1 == "-d")
		{
			string key;
			getpassword("Enter blowfish key",key);			
			std::streamoff size;
			if(!filesize(arg2,size))
			{
				cout << "Error reading input file!\r\n";
				return 0;
			}
			unsigned char *buffer;
			readfile(argv[2],&buffer,size);
			unsigned char *bufferout;
			bufferout = new unsigned char [size+1];		
			memset(bufferout,'\0',size+1);
			if(!decrypt(key,buffer,bufferout,size))
			{
				delete [] bufferout;
				delete [] buffer;
				cout << "Decrypt error\r\n";
				return 0;
			}
			if(!writefile(arg3,bufferout,size))
			{
				cout << "Write error\r\n";
			}
			delete [] bufferout;
			delete [] buffer;
			cout << "Decrypt done\n";
		}
		else if(arg1 == "-e")
		{
			string key;
			getpassword("Enter blowfish key",key);
			string key2;
			getpassword("Enter blowfish key again",key2);
			if(key != key2)
			{
				cout << "Pass does not match!\r\n";
				return 0;
			}
			std::streamoff size;
			if(!filesize(argv[2],size))
			{
				cout << "Error reading input file!\r\n";
				return 0;
			}
			unsigned char *buffer;
			readfile(arg2,&buffer,size);
			unsigned char *bufferout;
			bufferout = new unsigned char [size+1];		
			memset(bufferout,'\0',size+1);
			if(!encrypt(key,buffer,bufferout,size))
			{
				delete [] bufferout;
				delete [] buffer;
				cout << "Encrypt error\r\n";
				return 0;
			}
			if(!writefile(arg3,bufferout,size))
			{
				cout << "Write error\r\n";
			}
			delete [] bufferout;
			delete [] buffer;
			cout << "Encrypt done\n";
		}
		else
		{
			cout << "error\n";
		}
	}
	return 1;
}
