/******************************************************************************
* File:        Daa_certify.h
* Description: DAA certify - test routines from Pseudonym creation protocol
*
* Author:      Chris Newton
*
* Created:     Monday 9 July 2018
*
* (C) Copyright 2018, University of Surrey.
*
******************************************************************************/

#pragma once

#include <array>
#include <iostream>
#include "Tss_includes.h"
#include "Byte_buffer.h"
#include "Openssl_ec_utils.h"
#include "Tpm_utils.h"
#include "Tpm_error.h"

using Point_set=std::array<G1_point,4>;
using Certify_data=std::array<Byte_buffer,3>;

Certify_data complete_daa_certify(
TSS_CONTEXT* tss_context,
TPM_HANDLE daa_key_handle,
TPM_HANDLE psk_handle,
uint16_t counter,
Byte_buffer const& qd
);
