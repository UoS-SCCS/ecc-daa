/*******************************************************************************
* File:        Number_conversions.cpp
* Description: Number conversion routines
*
* Author:      Chris Newton
* Created:     Tuesday 3 April 2018
*
* (C) Copyright 2018, University of Surrey.
*
*******************************************************************************/

/*******************************************************************************
*                                                                              *
* (C) Copyright 2019 University of Surrey                                      *
*                                                                              *
* Redistribution and use in source and binary forms, with or without           *
* modification, are permitted provided that the following conditions are met:  *
*                                                                              *
* 1. Redistributions of source code must retain the above copyright notice,    *
* this list of conditions and the following disclaimer.                        *
*                                                                              *
* 2. Redistributions in binary form must reproduce the above copyright notice, *
* this list of conditions and the following disclaimer in the documentation    *
* and/or other materials provided with the distribution.                       *
*                                                                              *
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"  *
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE    *
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE   *
* ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE    *
* LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR          *
* CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF         *
* SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS     *
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN      *
* CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)      *
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE   *
* POSSIBILITY OF SUCH DAMAGE.                                                  *
*                                                                              *
*******************************************************************************/


#include <openssl/bn.h>
#include <gmp.h>
#include <cstring>
#include "Number_conversions.h"

size_t bn2bin(BIGNUM const* bn, u8_ptr& bp)
{
	if (bp!=nullptr)
		free(bp);

	size_t sz=BN_num_bytes(bn);
	bp=static_cast<u8_ptr>(malloc(sz));
	BN_bn2bin(bn, bp);	

	return sz;
}

void bin2bn(u8_const_ptr b, size_t const b_size, BIGNUM* bn)
{
	BN_bin2bn(b,b_size,bn);
}

Byte_buffer bn2bb(BIGNUM const* bn)
{
	size_t sz=BN_num_bytes(bn);
	Byte_buffer bb(sz,0);
	BN_bn2bin(bn,&bb[0]);

	return bb;
}


