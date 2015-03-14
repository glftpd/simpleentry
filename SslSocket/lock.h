#ifndef LOCK_H
#define LOCK_H

#include "global.h"


/* 

class to create locks for threadsafe programming
get the lock with Lock() and release it with Unlock()

*/
class DLL Lock
{
public:

	Lock();

	~Lock();

	void lock(void);

	void unlock(void);

private:

#ifdef _WIN32
	HANDLE mutex;
#else
	pthread_mutex_t mutex;
#endif

};


#endif
