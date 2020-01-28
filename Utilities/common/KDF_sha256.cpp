/***************************************************************************
* File:        KDF_sha256.cpp
* Description: KDF functions using SHA256 as the hash algorithm (see
*              TPM Specification Part 1, pg.43 and NIST SP 800-108
*
* Author:      Chris Newton
* Created:     Wednesday 30 May 2018
*
* (C) Copyright 2018, University of Surrey.
*
****************************************************************************/

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
