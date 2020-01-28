/***************************************************************************
* File:        Openssl_utils.cpp
* Description: Utility functions for Openssl
*
* Author:      Chris Newton
* Created:     Monday 7 May 2018
*
* (C) Copyright 2018, University of Surrey.
*
****************************************************************************/

#include <cstdio>
#include "Openssl_utils.h"

void init_openssl(void)
{
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();
}

void cleanup_openssl(void)
{
	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();
	EVP_cleanup();
}

void handle_openssl_error(void)
{
    ERR_print_errors_fp(stderr);
}

std::string get_openssl_error(void)
{
    FILE *stream;
    char *buf=NULL;
    size_t len=0;

    stream = open_memstream (&buf, &len);
    if (stream == NULL)
    {
        return std::string("Unable to open a stream to retrieve the error");
    }

    ERR_print_errors_fp(stream);
    fflush (stream);
    fclose(stream);

    std::string ossl_err(buf);
    free(buf);

    return ossl_err;    
}


