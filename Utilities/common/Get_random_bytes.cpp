/*******************************************************************************
* File:        Get_Random_byte_generator.cpp
* Description: Get a set of pseudo-random bytes
*
*
* Author:      Chris Newton
* Created:     Wednesay 30 May 2018
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

#include <chrono>
#include "Get_random_bytes.h"

Random_byte_generator::Random_byte_generator(unsigned int seed)
{
	unsigned int clock_seed = std::chrono::system_clock::now().time_since_epoch().count();
	unsigned int s=seed?seed:clock_seed;
	dre.seed(s);
	rb=std::uniform_int_distribution<short>(0,0xff);
}

Byte_buffer Random_byte_generator::operator()(size_t number_of_bytes)
{
	Byte_buffer r_bytes(number_of_bytes,0);
	for (int i=0;i<number_of_bytes;++i)
	{
		r_bytes[i]=static_cast<Byte>(rb(dre));
	}

	return r_bytes;
}


Byte_buffer get_random_bytes(
size_t number_of_bytes,
unsigned int seed
)
{
	// Use the C++ PRNG for now
	std::default_random_engine dre(seed);
	std::uniform_int_distribution<short> rb(0, 0xFF);

	Byte_buffer result(number_of_bytes, 0); 

	result[0]=static_cast<Byte>(rb(dre));	// Discard the first value ?? 
                                        // Yes if seeding from time(NULL), see:
                                        // https://stackoverflow.com/questions/26475595
	for (int i = 0; i < number_of_bytes; ++i)
		result[i] =static_cast<Byte>(rb(dre));

	return result;
}
