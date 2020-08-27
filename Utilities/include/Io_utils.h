/*******************************************************************************
* File:        Io_utils.h
* Description: I/O utilities
*
* Author:      Chris Newton
* Created:     Wednesday 1 May 2013
*
* (C) Copyright 2013
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


#pragma once

#include <iostream>
#include <sstream>
#include <string>

// Define the appropriate directory seperators and their opposites
#ifndef _WIN32
//#define _MAX_FNAME 1024
const char dirSep='/';
const char altDirSep='\\';
#else
const char dirSep='\\';
const char altDirSep='/';
#endif

const int maxline=200;

std::string make_filename(
std::string const& baseDir,
std::string const& name
);

void eat_white(std::istream& is);

std::string str_tolower(
std::string const& str
);

void print_buffer(
std::ostream& os,
const uint8_t* buf,
size_t len,
bool remove_leading
);

template<typename T>
std::string vars_to_string(T const& t)
{
	std::ostringstream os;
	os << t;
	return os.str();
}

template<typename T, typename...Vargs>
std::string vars_to_string(T t, Vargs... args)
{
	std::ostringstream os;
	os << t;
	return os.str()+vars_to_string(args...);
}

