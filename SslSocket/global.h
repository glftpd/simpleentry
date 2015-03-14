#ifndef __GLOBAL_H
#define __GLOBAL_H
#define _MULTI_THREADED

#include <iostream>
#include <string>
#include <sstream>
#include <algorithm>
#include <vector>
#include <fstream>
#include <sstream>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <cctype>
#include <list>
#include <iomanip>

#ifdef _WIN32
#include "windows.h"
#include <winsock.h>
#include <winbase.h>
#pragma warning (disable:4251)
#else
#include "pthread.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#endif

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>

using namespace std;

#ifndef SOLARIS
#define SOLARIS (defined(sun) && (defined(__svr4__) || defined(__SVR4)))
#endif


#define version "SslSocket lib v.0.4.2 2011/02/07 (c) _hawk_/PPX"

#if SOLARIS
int
daemon(int nochdir, int noclose)
{
        int fd;

        switch (fork()) {
        case -1:
                return (-1);
        case 0:
                break;
        default:
                exit(0);
        }

        if (setsid() == -1)
                return (-1);

        if (!nochdir)
                (void)chdir("/");

        if (!noclose && (fd = open(PATH_DEVNULL, O_RDWR, 0)) != -1) {
                (void)dup2(fd, STDIN_FILENO);
                (void)dup2(fd, STDOUT_FILENO);
                (void)dup2(fd, STDERR_FILENO);
                if (fd > 2)
                        (void)close (fd);
        }
        return (0);
}
#endif

#ifdef _WIN32
#define DLL __declspec(dllexport)
#define daemon FreeConsole();
#else
#define DLL
#endif

#endif
