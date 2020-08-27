/*******************************************************************************
* File:        KDF_sha256.cpp
* Description: TPM KDFa function using SHA256 as the hash algorithm (see
*              TPM Specification 1.38, Part 1, pg.43 and NIST SP 800-108)
*			   also TPM KDFe function using SHA256 (see TPM specification 1.38,
			   Part 1, pg. 45 and NIST SP 800 56C)
*
* Author:      Chris Newton
* Created:     Wednesday 30 May 2018, KDFe added 11 July 2020
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


#include <iostream>
#include <cmath>
#include "KDF_sha256.h"

Byte_buffer KDFa_sha256(
Byte_buffer const& key,		// HMAC key
Byte_buffer const& label,	// label
Byte_buffer const& contextU,
Byte_buffer const& contextV,
uint32_t const size_in_bits,
bool once			// If true only perform 1 iteration 
)
{
	if (once) // ###### need to fix this for a full implementation ######
	{
		std::cerr << "The use of once is not implemented yet\n";
		exit(EXIT_FAILURE);	
	}

	Byte_buffer fixed_data=label;
	if (label[label.size()-1]!=0)
		fixed_data+=Byte_buffer{0x00};

	if (contextU.size()>0)
		fixed_data+=contextU;

	if (contextV.size()>0)
		fixed_data+=contextV;

	fixed_data+=uint32_to_bb(size_in_bits);

	Byte_buffer result=NIST_SP108_sha256_fd(key,fixed_data,size_in_bits);
//	std::cout << result.to_hex_string() << '\t';
	if (size_in_bits%8 !=0)
	{
		result[0]&=((1<<(size_in_bits%8))+0xff);
	}

	return result;
}

Byte_buffer NIST_SP108_sha256_fd(
Byte_buffer const& key,		// HMAC key
Byte_buffer const& fixed_input,
uint32_t const size_in_bits
)
{
	size_t size_in_bytes=(size_in_bits+7)/8;
	size_t n_hashes=std::ceil(static_cast<double>(size_in_bits)/256);
	Byte_buffer result;
	uint32_t counter=1;
	for (int i=0;i<n_hashes;++i)
	{
		Byte_buffer hmac_input=uint32_to_bb(counter)+fixed_input;
//		std::cout << "HMAC input: " << hmac_input.to_hex_string() << '\n';
		result+=hmac_sha256(key,hmac_input);
		counter++;
	}

	return result.get_part(0,size_in_bytes);
}


Byte_buffer NIST_SP56C_sha256_fd(
Byte_buffer const& key,
Byte_buffer const& fixed_input,
uint32_t const size_in_bits
)
{
	size_t size_in_bytes=(size_in_bits+7)/8;
	size_t n_hashes=std::ceil(static_cast<double>(size_in_bits)/256);
	Byte_buffer result;
	uint32_t counter=1;
	for (int i=0;i<n_hashes;++i)
	{
		Byte_buffer hash_input=uint32_to_bb(counter)+key+fixed_input;
		result+=sha256_bb(hash_input);
		counter++;
	}

	return result.get_part(0,size_in_bytes);
}

