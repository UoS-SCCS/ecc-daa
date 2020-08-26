/***************************************************************************
* File:        Daa_signatures.h
* Description: Common code for the DAA signatures (sign, certify and quote)
*
* Author:      Chris Newton
*
* Created:     Sunday 2 June 2019
*
* (C) Copyright 2019, University of Surrey.
*
****************************************************************************/

#pragma once

#include <iostream>
#include <string>
#include <map>
#include "Tss_setup.h"
#include "Tpm_error.h"
#include "Tpm_daa.h"
#include "Tpm_utils.h"
#include "Get_random_bytes.h"

enum Option {datadir,usebsn,nobsn,help,version,debug};

const std::map<std::string,Option> program_options{
    {"--datadir",datadir},
    {"-d",datadir},
    {"--bsn",usebsn},
    {"-b",usebsn},
    {"--nobsn",nobsn},
    {"-n",nobsn},
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
    Setup_ptr sp;
    std::string file_basename;
    std::string credential_filename;
    std::string signature_file;
    std::string run_number;
    bool use_basename;
};

void usage(std::ostream& os, std::string name);

enum Init_result {init_ok=0,init_failed,init_help};

Init_result initialise(int argc, char *argv[], std::string const& type, Program_data& pd);

enum Protocol_result {protocol_ok,protocol_failed};

Protocol_result run_protocol(Program_data& pd, Random_byte_generator& rbg);
