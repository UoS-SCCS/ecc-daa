/*****************************************************************************
* File:        Verify_daa_attest.h
* Description: Program to verify a DAA attestation signature
*
* Author:      Chris Newton
*
* Created:     Sunday 5 May 2019
*
* (C) Copyright 2019, University of Surrey, all rights reserved.
*
*****************************************************************************/
#pragma once

#include <iostream>
#include <map>
#include <string>

enum Init_result {init_ok=0,init_failed,init_help};

enum Option {datadir,help,version,debug};

const std::map<std::string,Option> program_options{
    {"--datadir",datadir},
    {"-d",datadir},
    {"--debug", debug},
    {"-g", debug},
    {"--help",help},
    {"-h",help},
    {"--version",version},
    {"-v",version}
};

struct Program_data
{
    std::string file_basename;
    std::string attest_filename;
    std::string run_number;
    bool use_basename;
};

void usage(std::ostream& os, const char* name);

Init_result initialise(int argc, char *argv[], Program_data& pd);

enum Verify_result {verify_ok,verify_failed};

Verify_result verify(Program_data& pd);

bool check_key_name(Byte_buffer cert, Byte_buffer const& qk_pd);

bool check_pcr_value(Byte_buffer cert);
