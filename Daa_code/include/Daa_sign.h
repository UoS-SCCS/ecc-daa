/*******************************************************************************
* File:        Daa_sign.h
* Description: Routines for DAA sign operation
*
* Author:      Chris Newton
*
* Created:     Monday 18 June 2018
*
* (C) Copyright 2018, University of Surrey.
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

#include <chrono>
#include <fstream>
#include "Tss_includes.h"
#include "Byte_buffer.h"
#include "Openssl_ec_utils.h"

using Idv=std::pair<uint16_t,G1_point>;

Idv start_daa_validation(
	TSS_CONTEXT* tssContext,
	TPM_HANDLE daa_key_handle
);

using Cdj=std::pair<Byte_buffer,Byte_buffer>;
Cdj complete_daa_sign(
TSS_CONTEXT* tssContext,
TPM_HANDLE daa_key_handle,
uint16_t counter,
Byte_buffer const& p
);
