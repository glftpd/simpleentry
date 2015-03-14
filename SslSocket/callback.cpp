#include "callback.h"






#ifdef _WIN32
static HANDLE *lock_cs = NULL;

void win32_locking_callback(int mode, int type, const char *file, int line)
{	
	if (mode & CRYPTO_LOCK)
	{
		WaitForSingleObject(lock_cs[type],INFINITE);
	}
	else
	{
		ReleaseMutex(lock_cs[type]);
	}
}

void thread_setup(void)
{
	if(lock_cs == NULL)
	{
		int i;

		lock_cs = (HANDLE *)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(HANDLE));
		for (i = 0; i < CRYPTO_num_locks(); i++)
		{
			lock_cs[i]=CreateMutex(NULL,FALSE,NULL);
		}

		CRYPTO_set_locking_callback((void (*)(int,int,const char *,int))win32_locking_callback);
	}
}

void thread_cleanup(void)
{
	if(lock_cs != NULL)
	{
		int i;

		CRYPTO_set_locking_callback(NULL);
		for (i=0; i<CRYPTO_num_locks(); i++)
		{
			CloseHandle(lock_cs[i]);
		}
		OPENSSL_free(lock_cs);
	}
}
#else

#define MUTEX_TYPE	pthread_mutex_t
#define MUTEX_SETUP(x)	pthread_mutex_init(&(x),NULL)
#define MUTEX_CLEANUP(x)	pthread_mutex_destroy(&(x))
#define MUTEX_LOCK(x)	pthread_mutex_lock(&(x))
#define MUTEX_UNLOCK(x)	pthread_mutex_unlock(&(x))
#define THREAD_ID	pthread_self()


struct CRYPTO_dynlock_value
{
	MUTEX_TYPE mutex;
};

static MUTEX_TYPE *mutex_buf = NULL;




static void locking_function(int mode, int n, const char * file, int line)
{
	stringstream ss;
	ss << mode << n << file << line;
	if (mode & CRYPTO_LOCK)
	{
		MUTEX_LOCK(mutex_buf[n]);
	}
	else
	{
		MUTEX_UNLOCK(mutex_buf[n]);
	}
}

static unsigned long id_function(void)
{
	return ((unsigned long)THREAD_ID);
}

static struct CRYPTO_dynlock_value * dyn_create_function(const char *file, int line)
{
	stringstream ss;
	ss << file << line;
	struct CRYPTO_dynlock_value *value;
	value = (struct CRYPTO_dynlock_value *)malloc(sizeof(struct CRYPTO_dynlock_value));
	if (!value)
	{
		return NULL;
	}
	MUTEX_SETUP(value->mutex);
	return value;
}

static void dyn_lock_function(int mode, struct CRYPTO_dynlock_value *l, const char *file, int line)
{
	stringstream ss;
	ss << mode << file << line;
	if (mode & CRYPTO_LOCK)
	{
		MUTEX_LOCK(l->mutex);
	}
	else
	{
		MUTEX_UNLOCK(l->mutex);
	}
}

static void dyn_destroy_function(struct CRYPTO_dynlock_value *l, const char *file, int line)
{
	stringstream ss;
	ss << file << line;
	MUTEX_CLEANUP(l->mutex);
	free(l);
}


int thread_setup(void)
{
	int i;
	
	mutex_buf = (MUTEX_TYPE *)malloc(CRYPTO_num_locks() * sizeof(MUTEX_TYPE));
	if (!mutex_buf)
	{
		return 0;
	}
	for (i = 0; i < CRYPTO_num_locks(); i++)
	{
		MUTEX_SETUP(mutex_buf[i]);
	}
	CRYPTO_set_id_callback(id_function);
	CRYPTO_set_locking_callback(locking_function);
	
	CRYPTO_set_dynlock_create_callback(dyn_create_function);
	CRYPTO_set_dynlock_lock_callback(dyn_lock_function);
	CRYPTO_set_dynlock_destroy_callback(dyn_destroy_function);
	
	return 1;
}

int thread_cleanup(void)
{
	int i;
	
	if (!mutex_buf)
	{
		return 0;
	}
	CRYPTO_set_id_callback(NULL);
	CRYPTO_set_locking_callback(NULL);
	CRYPTO_set_dynlock_create_callback(NULL);
	CRYPTO_set_dynlock_lock_callback(NULL);
	CRYPTO_set_dynlock_destroy_callback(NULL);
	for (i = 0; i < CRYPTO_num_locks(); i++)
	{
		MUTEX_CLEANUP(mutex_buf[i]);
	}
	free(mutex_buf);
	mutex_buf = NULL;
	return 1;
}

#endif


DH *tmp_dh_cb(SSL *ssl, int is_export, int keylength)
{	
	return BaseSock::globaldh;	
}

int dh_callback(SSL_CTX *ctx, char *filename)
{	
	BIO *bio = NULL;
	bio = BIO_new_file(filename,"r");

	if(bio != NULL)
	{
		BaseSock::globaldh = PEM_read_bio_DHparams(bio,NULL,NULL,NULL);
		BIO_free(bio);
		SSL_CTX_set_tmp_dh_callback(ctx, tmp_dh_cb);
		return 1;
	}
	else
	{
		return 0;
	}
		
}



int _BaseInit(void)
{
	#ifdef _WIN32
	WSADATA wsa;
	if (WSAStartup(MAKEWORD(1, 1), &wsa))
	{		
		return 0;
	}	
	#endif
	SSL_load_error_strings();
	SSL_library_init();
	thread_setup();
	return 1;
}



