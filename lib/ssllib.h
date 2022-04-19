#ifndef __SSLLIB_H__
#define __SSLLIB_H__


#include <openssl/ssl.h>



#if OPENSSL_VERSION_NUMBER >= 0x30000000L
extern EVP_MAC *rtpe_evp_hmac;
#endif



void rtpe_ssl_init(void);


#endif
