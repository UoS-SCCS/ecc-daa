/******************************************************************************
* File:        Hex_string.h
* Description: Hex_string class for parameter passing in VANET demonstrator
*              It MUST NOT throw
*
* Created:     Saturday 30 June 2018
*
*
******************************************************************************/

#pragma once

#include <cstdint>
#include <string>
#include <vector>

using Byte=unsigned char;

/******************************************************************************
*
* This is a class, used for parameter passing in the VANET demonstrator
* The Java bignumber class has routines for conversion to and from hexadecimal
* strings. For conversion to a Byte_buffer the hexadecimal string must have an
* even number of characters (whole bytes) so if the hexadecimal string has an
* odd number of characters a zero will be added to the front (MSB).
*
* It must not throw and so will return a result code (0 for success) and will
* provide a get_last_error() member so that failures can be logged. Calling
* get_last_error() will reset the error string.
*
* To confirm that a contructor succeeded, call the meber function is_valid().
*
******************************************************************************/

class Hex_string
{
public:
	Hex_string() : valid_(false) {}
	explicit Hex_string(std::string const& str);
	Hex_string(Hex_string const& hs)=default;
	Hex_string(Hex_string&& hs)=default;
	Hex_string& operator=(Hex_string const& hs)=default;
	bool is_valid() const {return valid_;}
	size_t size() const {return hex_string_.size();}
	std::string hex_string() const;
	std::string get_last_error();

private:
	bool valid_;
	std::string hex_string_;
	std::string error_;
};


