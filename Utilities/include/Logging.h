/*******************************************************************************
* File:        Logging.h
* Description: Routines for logging errors and data
*
* Created:     Monday 15 October 2018
*
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

#include <iosfwd>
#include <streambuf>
#include <fstream>
#include <string>
#include <memory>

class Log;
using Log_ptr=std::unique_ptr<Log>;
extern Log_ptr log_ptr;

/*
Idea for a Null stream from:

	https://stackoverflow.com/questions/11826554/standard-no-op-output-stream

also see the example in:

	Josuttis - The Standard C++ Library, Second Edition, Pg. 833

*/

class Null_buffer : public std::streambuf
{
public:
	Null_buffer()=default;
	int overflow(int c) { return c; }
	~Null_buffer()=default;	
};

class Null_stream : public std::ostream
{
public: 
  Null_stream() : std::ostream(&m_sb) {}

private:
 Null_buffer m_sb;
};


class Log
{
public:
	Log() : debug_(0) {}
	virtual std::ostream& os()=0;
	virtual void write_to_log(std::string str)=0;
	void set_debug_level(uint dl) {debug_=dl;}
	uint  debug_level() const {return debug_;}
	virtual ~Log()=default;

private:
	uint debug_;
};

class Null_log : public Log
{
public:	
	virtual std::ostream& os() {return null_stream_;}
	virtual void write_to_log(std::string str){}
	virtual ~Null_log() throw()=default;
private:
    Null_stream null_stream_;
};

class Cout_log : public Log
{
public:	
	virtual std::ostream& os() {return std::cout;}
	virtual void write_to_log(std::string str){std::cout << str << std::flush;}
	virtual ~Cout_log()=default;
};

class Timed_cout_log : public Log
{
public:	
	virtual std::ostream& os();
	virtual void write_to_log(std::string str);
	virtual ~Timed_cout_log()=default;
};

class File_log : public Log
{
public:
	File_log()=delete;
	explicit File_log(std::string filename);
	virtual std::ostream& os() {return os_;}
	virtual void write_to_log(std::string str){os_ << str << std::flush;}
	virtual ~File_log();
private:
	std::ofstream os_;
};

class Timed_file_log : public Log
{
public:
	Timed_file_log()=delete;
	explicit Timed_file_log(std::string filename);
	virtual std::ostream& os();
	virtual void write_to_log(std::string str);
	virtual ~Timed_file_log();
private:
	std::ofstream os_;
};

std::string generate_log_number();

std::string generate_log_filename(
std::string const& base_dir,
std::string const& prefix
);

