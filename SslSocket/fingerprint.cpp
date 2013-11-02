#include "fingerprint.h"
#include "strings.h"


string _fingerprint(SSL *ssl)
{
	X509 *cert = NULL;	
	string tmpres;
	cert = SSL_get_peer_certificate(ssl);
	

	if(cert == NULL)
	{		
		return "NO-FINGERPRINT";		
	}
	else
	{
		unsigned char keyid[EVP_MAX_MD_SIZE];
		unsigned int keyidlen;
		if(!X509_digest(cert,EVP_md5(),keyid, &keyidlen))
		{			
			X509_free(cert);
			return "NO-FINGERPRINT";			
		}
		else
		{
			X509_free(cert);
			stringstream res;
			for(unsigned int k = 0; k < keyidlen; k++)
			{
				res << hex << setfill('0') << setw(2) << (int)keyid[k];
				if(k != (keyidlen -1)) res << ":";
			}
			
			return toupper(res.str());
			
		}
	}	
}






