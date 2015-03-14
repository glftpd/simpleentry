#include "thread.h"

void *makethread(void* threadclass)
{ 
#ifdef _WIN32
	Thread* thread = static_cast<Thread*>(threadclass);
	thread->run();
	if(thread->autoDelete())
	{
		delete thread;
	}
	return NULL;
#else
	Thread* thread = (Thread*)threadclass;
	thread->run();
	if(thread->autoDelete())
	{
		delete thread;
	}
	return NULL;
#endif
}

Thread::~Thread()
{
	_autoDelete = true;
}

Thread::Thread()
{	
}

void Thread::run()
{
	loop();
}

void Thread::autoDelete(bool autoDelete)
{
	_autoDelete = autoDelete;
}

bool Thread::autoDelete(void)
{
	return _autoDelete;
}

void Thread::start(Thread* t)
{
#ifdef _WIN32
	t->hThread = CreateThread(NULL, 2000, (LPTHREAD_START_ROUTINE)makethread, t, 0, &t->tid);
#else
	pthread_attr_t threadattr;
	pthread_attr_init(&threadattr);
	pthread_attr_setdetachstate(&threadattr,PTHREAD_CREATE_DETACHED);
	pthread_create(&t->tid,&threadattr,makethread,t);
#endif
}

void Thread::join(void)
{
#ifdef _WIN32
	WaitForSingleObject(hThread, INFINITE);
#else
	void*status;
	pthread_join(tid, &status);
#endif
}

void Thread::sleep(int ms)
{
#ifdef _WIN32
	Sleep(ms);
#else
	usleep(ms * 1000);
#endif
}
