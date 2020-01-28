/***************************************************************************************
* File:        Get_Random_byte_generator.cpp
* Description: Get a set of pseudo-random bytes
*
*
* Author:      Chris Newton
* Created:     Wednesay 30 May 2018
*
* (C) Copyright 2018, University of Surrey.
*
***************************************************************************************/
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
