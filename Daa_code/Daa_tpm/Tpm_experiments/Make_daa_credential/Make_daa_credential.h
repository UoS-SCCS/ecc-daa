/*****************************************************************************
* File:        Make_daa_credential.h
* Description: Program to generate the credential for a DAA key
*
* Author:      Chris Newton
*
* Created:     Saturday 4 May 2019
*
* (C) Copyright 2019, University of Surrey, all rights reserved.
*
*****************************************************************************/
#include <iostream>
#include <string>
#include <map>
#include "Tss_setup.h"
#include "Tpm_error.h"
#include "Tpm_daa.h"
#include "Tpm_utils.h"
#include "Get_random_bytes.h"

enum Init_result {init_ok=0,init_failed,init_help};

enum Option {datadir,usedev,usesim,help,version,debug};

const std::map<std::string,Option> program_options{
    {"--datadir",datadir},
    {"-d",datadir},
    {"--dev",usedev},
    {"-t",usedev},
    {"--sim",usesim},
    {"-s",usesim},
    {"--debug", debug},
    {"-g", debug},
    {"--help",help},
    {"-h",help},
    {"--version",version},
    {"-v",version}
};

struct Program_data
{
    Tpm_daa tpm;
    Byte_buffer ek_bb;
    Setup_ptr sp;
    std::string file_basename;
    std::string run_number;
};

void usage(std::ostream& os, const char* name);

Init_result initialise(int argc, char *argv[], Program_data& pd);

enum Protocol_result {protocol_ok,protocol_failed};

Protocol_result run_protocol(Program_data& pd, Random_byte_generator& rbg);
