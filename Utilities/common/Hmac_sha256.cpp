/***************************************************************************************
* File:        Hmac_sha256.cpp
* Description: Code to generate the HMAC using SHA256
*
*
* Author:      Chris Newton
* Created:     Saturday 10 March 2018
*
* (C) Copyright 2018, University of Surrey.
*
***************************************************************************************/

#include <openssl/hmac.h>
#include "Byte_buffer.h"
#include "Hmac.h"

Byte_buffer hmac_sha256(Byte_buffer const& key, Byte_buffer const& data)
{
	unsigned int len = 32; // The length of the sha256 hash
	Byte_buffer result(len, 0);

	Hmac_ctx_ptr ctx=new_hmac_ctx();
	HMAC_CTX_reset(ctx.get());

	// Using sha256 hash engine here.
	HMAC_Init_ex(ctx.get(), &key[0], key.size(), EVP_sha256(), NULL);
	HMAC_Update(ctx.get(), &data[0], data.size());
	HMAC_Final(ctx.get(), &result[0], &len);

	return result;
}

