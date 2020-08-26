/******************************************************************************
* File:        Daa_sign.h
* Description: Routines for DAA sign operation
*
* Author:      Chris Newton
*
* Created:     Monday 18 June 2018
*
* (C) Copyright 2018, University of Surrey.
*
******************************************************************************/

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
