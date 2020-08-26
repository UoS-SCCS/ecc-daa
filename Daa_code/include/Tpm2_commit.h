/******************************************************************************
* File:        Tpm2_commit.h
* Description: Routine to call and time TPM2_commit
*
* Author:      Chris Newton
*
* Created:     Saturday 15 September 2018
*
* (C) Copyright 2018, University of Surrey.
*
******************************************************************************/

#pragma once

#include "Tss_includes.h"
#include <array>
#include <iostream>
#include "Byte_buffer.h"
#include "Openssl_ec_utils.h"
#include "Tpm_utils.h"
#include "Tpm_error.h"

using Commit_points=std::array<G1_point,3>;
using Commit_data=std::pair<uint16_t, Commit_points>;

Commit_data tpm2_commit(
TSS_CONTEXT* tssContext,
TPM_HANDLE daa_key_handle,
G1_point const& pt_s,
G1_point const& mapping_point
);

void print_commit_data(
std::ostream& os,    
Commit_data const& cd
);

