/*******************************************************************************
* File:        Make_credential.cpp
* Description: Implement make credential, using TPM and without the TPM
*
* Author:      Chris Newton
*
* Created:     Wednesday 13 June 2018
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

#include <iostream>
#include <string>
#include "Get_random_bytes.h"
#include "Byte_buffer.h"

// credential data is (secret, credential_blob)
using Credential_data=std::pair<Byte_buffer,Byte_buffer>;

const Byte_buffer nul{0x00};
const Byte_buffer identity_str=Byte_buffer("IDENTITY");
const Byte_buffer storage_str=Byte_buffer("STORAGE");
const Byte_buffer integrity_str=Byte_buffer("INTEGRITY");

const uint16_t seed_bytes=32;   // Same as for SHA256

Credential_data make_credential_TPM(
TSS_CONTEXT* tss_context,
TPM2B_PUBLIC const& ek_public, 
TPM2B_PUBLIC const& daa_public_data,
Byte_buffer const& credential_key
);

Credential_data make_credential_issuer(
Byte_buffer const& ek_public_key,
TPM2B_PUBLIC const& daa_public_data,
Byte_buffer const& credential_key,
Random_byte_generator& rbg
);
