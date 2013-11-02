#ifndef CALLBACK_H
#define CALLBACK_H

#include "global.h"
#include "basesock.h"


	DLL int _BaseInit(void);
	DH *tmp_dh_cb(SSL *ssl, int is_export, int keylength);

#endif
