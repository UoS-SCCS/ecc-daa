/*****************************************************************************
* File:        Provision_tpm.h
* Description: Program to provision a TPM after reset
*
* Author:      Chris Newton
*
* Created:     Saturday 25 May 2019
*
* (C) Copyright 2019, University of Surrey, all rights reserved.
*
*****************************************************************************/

#pragma once

#include <iostream>
#include <map>
#include <string>
#include "Tpm_error.h"
#include "Byte_buffer.h"

enum Option {usedev,usesim,debug,help,version};

const std::map<std::string,Option> program_options{
    {"--tpm",usedev},
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

void usage(std::ostream& os, const char* name);


