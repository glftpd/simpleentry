#include "dh1080.h"
#include <cstring>

namespace SslSocket
{
	const char *prime1080 = "FBE1022E23D213E8ACFA9AE8B9DFADA3EA6B7AC7A7B7E95AB5EB2DF858921FEADE95E6AC7BE7DE6ADBAB8A783E7AF7A7FA6A2B7BEB1E72EAE2B72F9FA2BFB2A2EFBEFAC868BADB3E828FA8BADFADA3E4CC1BE7E8AFE85E9698A783EB68FA07A77AB6AD7BEB618ACF9CA2897EB28A6189EFA07AB99A8A7FA9AE299EFA7BA66DEAFEFBEFBF0B7D8B";
	unsigned char B64[] = "./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	unsigned char B64ABC[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	unsigned char b64buf[256];

	void initb64()
	{
		unsigned int i;
		for (i=0; i<256; i++) b64buf[i]=0x00;
		for (i=0; i<64; i++) b64buf[(B64ABC[i])]=i;
	}



	int b64toh(char *b, char *d)
	{
		int i;
		unsigned int k,l;

		l = strlen(b);
		if (l < 2) return 0;
		for (i = l-1; i > -1; i--)
		{
			if (b64buf[((unsigned int)b[i])]==0) l--;
			else break;
		}

		if (l<2) return 0;
		i=0, k=0;
		while (1)
		{
			i++;
			if (k+1<l) d[i-1]=((b64buf[((unsigned int)b[k])])<<2);
			else break;
			k++;
			if (k<l) d[i-1]|=((b64buf[((unsigned int)b[k])])>>4);
			else break;
			i++;
			if (k+1<l) d[i-1]=((b64buf[((unsigned int)b[k])])<<4);
			else break;
			k++;
			if (k<l) d[i-1]|=((b64buf[((unsigned int)b[k])])>>2);
			else break;
			i++;
			if (k+1<l) d[i-1]=((b64buf[((unsigned int)b[k])])<<6);
			else break;
			k++;
			if (k<l) d[i-1]|=(b64buf[((unsigned int)b[k])]);
			else break;
			k++;
		}
		return i-1;
	}

	int htob64(char *h, char *d, unsigned int l)
	{
		unsigned int i,j,k;
		unsigned char m,t;

		if (!l) return 0;
		l<<=3;                              // no. bits
		m=0x80;
		for (i=0,j=0,k=0,t=0; i<l; i++)
		{
			if (h[(i>>3)]&m) t|=1;
			j++;
			if (!(m>>=1)) m=0x80;
			if (!(j%6))
			{
				d[k]=B64ABC[t];
				t&=0;
				k++;
			}
			t<<=1;
		}
		m=5-(j%6);
		t<<=m;
		if (m)
		{
			d[k]=B64ABC[t];
			k++;
		}
		d[k]&=0;
		return strlen(d);
	}


	int base64dec(char c)
	{
		int i;

		for (i = 0; i < 64; i++)
			if (B64[i] == c) return i;

		return 0;
	}

	int DH1080_gen(unsigned char *Priv_Key, int &privlen, unsigned char *Pub_Key, int &publen)
	{
		unsigned long len;

		DH *dh = NULL;
		BIGNUM *b_prime = NULL;
		BIGNUM *b_generator = NULL;

		initb64();
		dh = DH_new();

		if(dh == NULL)
		{
			return 0;
		}

		if (!BN_hex2bn(&b_prime, prime1080))
		{
			DH_free(dh);
			return 0;
		}

		if (!BN_dec2bn(&b_generator, "2"))
		{
			if(b_prime != NULL) OPENSSL_free(b_prime);
			DH_free(dh);
			return 0;
		}


#if OPENSSL_VERSION_NUMBER < 0x10100000L
		dh->p = b_prime;
		dh->g = b_generator;
#else
		DH_set0_pqg(dh, b_prime, NULL, b_generator);
#endif

		if (!DH_generate_key(dh))
		{
			DH_free(dh);
			return 0;
		}

		unsigned char *a,*b;
		unsigned char *a_,*b_;

		const BIGNUM *pub_key, *priv_key;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
		priv_key = dh->priv_key;
		pub_key = dh->pub_key;
#else
		DH_get0_key(dh, &pub_key, &priv_key);
#endif
		len = BN_num_bytes(priv_key);

		a_ = (unsigned char *)malloc(200);
		a = (unsigned char *)malloc(len);


		BN_bn2bin(priv_key, a);

		htob64((char *)a, (char *)a_, len);

		privlen = (int)strlen((const char *)a_);
		free(a);

		for(int i=0; i < privlen;i++)
		{
			Priv_Key[i] = a_[i];
		}
		free(a_);


		len = BN_num_bytes(pub_key);

		b_ = (unsigned char *)malloc(200);
		b = (unsigned char *)malloc(len);

		BN_bn2bin(pub_key, b);

		htob64((char *)b, (char *)b_, len);

		publen = (int)strlen((const char *)b_);
		free(b);
		for(int i=0; i < publen;i++)
		{
			Pub_Key[i] = b_[i];
		}
		free(b_);

		DH_free(dh);

		return 1;
	}



	int DH1080_comp(unsigned char *Priv_Key, unsigned char *OtherPub_Key, unsigned char *Secret_Key, int &secretlen)
	{
		int len;
		unsigned char SHA256digest[32];
		char *key;
		BIGNUM *b_prime = NULL;
		BIGNUM *b_myPrivkey = NULL;
		BIGNUM *b_HisPubkey = NULL;
		BIGNUM *b_generator = NULL;
		DH *dh = NULL;

		unsigned char raw_buf[200];

		dh = DH_new();

		if(dh == NULL)
		{
			return 0;
		}

		if (!BN_hex2bn(&b_prime, prime1080))
		{
			DH_free(dh);
			return 0;
		}

		if (!BN_dec2bn(&b_generator, "2"))
		{
			if(b_prime != NULL) OPENSSL_free(b_prime);
			DH_free(dh);
			return 0;
		}



#if OPENSSL_VERSION_NUMBER < 0x10100000L
		dh->p = b_prime;
		dh->g = b_generator;
#else
		DH_set0_pqg(dh, b_prime, NULL, b_generator);
#endif

		memset(raw_buf, 0, 200);
		len = b64toh((char *)Priv_Key, (char *)raw_buf);
		b_myPrivkey = BN_bin2bn(raw_buf, len, NULL);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
		dh->priv_key = b_myPrivkey;
#else
		DH_set0_key(dh, NULL, b_myPrivkey);
#endif

		memset(raw_buf, 0, 200);
		len = b64toh((char *)OtherPub_Key, (char *)raw_buf);

		b_HisPubkey = BN_bin2bn(raw_buf, len, NULL);

		key = (char *)malloc(DH_size(dh));
		memset(key, 0, DH_size(dh));
		len = DH_compute_key((unsigned char *)key, b_HisPubkey, dh);
		SHA256_CTX c;
		SHA256_Init(&c);
		memset(SHA256digest, 0, 32);
		SHA256_Update(&c, key, len);
		SHA256_Final(SHA256digest, &c);
		memset(raw_buf, 0, 200);
		secretlen = htob64((char *)SHA256digest, (char *)raw_buf, 32);

		for(int i=0; i < secretlen;i++)
		{
			Secret_Key[i] = raw_buf[i];
		}
		DH_free(dh);
		BN_clear_free(b_HisPubkey);
		free(key);
		return 1;
	}

}
