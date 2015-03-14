#include "lock.h"



Lock::Lock()
{
#ifdef _WIN32	
	mutex = CreateMutex (NULL, FALSE, NULL);
#else
	pthread_mutex_init(&mutex, NULL);
#endif
}

Lock::~Lock()
{
#ifdef _WIN32
	CloseHandle(mutex);
	mutex = NULL;
#else
	pthread_mutex_destroy(&mutex); 
#endif
}

void Lock::lock(void)
{
#ifdef _WIN32
	WaitForSingleObject(mutex, INFINITE);
#else
	pthread_mutex_lock(&mutex);	
#endif
}

void Lock::unlock(void)
{
#ifdef _WIN32
	ReleaseMutex(mutex);
#else
	pthread_mutex_unlock(&mutex);
#endif
}
