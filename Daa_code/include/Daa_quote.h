/******************************************************************************
* File:        Daa_quote.h
* Description: DAA quote - routine for TPM2_Quote
*
* Author:      Chris Newton
*
* Created:     Saturday 15 Septemeber 2018
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


using Quote_data=std::array<Byte_buffer,3>;

Quote_data complete_daa_quote(
TSS_CONTEXT* tss_context,
TPM_HANDLE daa_key_handle,
TPML_PCR_SELECTION const& pcr_sel,
uint16_t counter,
Byte_buffer const& qd
);
