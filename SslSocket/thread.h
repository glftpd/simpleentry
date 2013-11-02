#ifndef THREAD_H
#define THREAD_H

#include "global.h"

class DLL Thread
{
	friend void *makethread(void* threadclass);

public:

	virtual void loop(void)=0;	
	void start(Thread *);
	virtual ~Thread();
	Thread();
	void join(void);
	void sleep(int ms);
	void autoDelete(bool autoDelete);
	bool autoDelete(void);

protected:
	bool _autoDelete;
	void run(void);

#ifdef _WIN32
	HANDLE hThread;
	unsigned long tid;
#else
	pthread_t tid;
#endif

};

#endif
