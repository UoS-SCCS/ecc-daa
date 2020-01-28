/*******************************************************************************
* File:        Make_daa_credential.h
* Description: Program to generate the credential for a DAA key
*
* Author:      Chris Newton
*
* Created:     Saturday 4 May 2019
*
* (C) Copyright 2019, University of Surrey, all rights reserved.
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

void usage(std::ostream& os, std::string name);

Init_result initialise(int argc, char *argv[], Program_data& pd);

enum Protocol_result {protocol_ok,protocol_failed};

Protocol_result run_protocol(Program_data& pd, Random_byte_generator& rbg);
