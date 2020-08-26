/******************************************************************************
* File:        Make_credential.cpp
* Description: Implement make credential, using TPM and without the TPM
*
* Author:      Chris Newton
*
* Created:     Wednesday 13 June 2018
*
* (C) Copyright 2018, University of Surrey.
*
******************************************************************************/

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
