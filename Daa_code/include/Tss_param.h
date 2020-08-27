/*******************************************************************************
* File:        Tss_param.h
* Description: Parameters used setting up IBM TSS
*
* Author:      Chris Newton
*
* Created:     Friday 20 April 2018
*
* (C) Copyright 2018, University of Surrey, all rights reserved.
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

#include "Tss_includes.h"

struct Tss_property
{
    int type;
    const char* value;
};

namespace Tss_default{
    // default options for the simulator
    Tss_property const sim_interface{TPM_INTERFACE_TYPE,"socsim"};
    // default options for "socsim" interface (when specified)
    Tss_property const server_type{TPM_SERVER_TYPE,"mssim"};
    Tss_property const server_name{TPM_SERVER_NAME,"localhost"};
    Tss_property const command_port{TPM_COMMAND_PORT,"2321"};
    Tss_property const platform_port{TPM_PLATFORM_PORT,"2322"};

    // default options for the hardware interface
    Tss_property const hw_interface{ TPM_INTERFACE_TYPE,"dev" };
    // single user option for "dev" interface (when specified)
    Tss_property const tpm_device{TPM_DEVICE,"/dev/tpm0"};

    // Other default options
    Tss_property const data_dir{TPM_DATA_DIR,"."};
    Tss_property const encrypt_sessions{TPM_ENCRYPT_SESSIONS,"1"};
    Tss_property const trace_level{TPM_TRACE_LEVEL,"0"};
}

// Possible overides for the TSS property defaults
namespace Tss_option {
    Tss_property const pi_data_dir{TPM_DATA_DIR,"/home/pi/TPM_data"};
    Tss_property const sim_data_dir{TPM_DATA_DIR,"/home/cn0016/TPM_data"};

    Tss_property const plaintext_sessions{TPM_ENCRYPT_SESSIONS,"0"};

    Tss_property const server_raw{TPM_SERVER_TYPE,"raw"};
    Tss_property const server_single{TPM_SERVER_TYPE,"rawsingle"};

    Tss_property const trace_1{TPM_TRACE_LEVEL,"1"};
    Tss_property const trace_2{TPM_TRACE_LEVEL,"2"};
}

