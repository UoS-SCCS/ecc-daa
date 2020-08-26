/***************************************************************************************
* File:        Get_random_bytes.h
* Description: Get a set of pseudo-random bytes
*
*
* Author:      Chris Newton
* Created:     Wednesay 30 May 2018
*
* (C) Copyright 2018, University of Surrey.
*
***************************************************************************************/
#pragma once

#include <random>
#include "Byte_buffer.h"

class Random_byte_generator
{
public:
    explicit Random_byte_generator(unsigned int seed=0);
    Byte_buffer operator()(size_t number_of_bytes);

private:
	// Use the C++ PRNG for now
    std::default_random_engine dre;
	std::uniform_int_distribution<short> rb;
};


Byte_buffer get_random_bytes(
size_t number_of_bytes,
unsigned int seed
);

