/******************************************************************************
* File:        Display_public_data.h
* Description: Display a key's public data (TPMT_PUBLIC)
*
* Author:      Chris Newton
*
* Created:     Friday 6 July 2018
*
* (C) Copyright 2018, University of Surrey.
*
******************************************************************************/

#pragma once

#include <iostream>
#include "Tss_includes.h"
#include "Byte_buffer.h"

void display_rsa_public_bb(
std::ostream& os,
Byte_buffer& pd_bb      
);

void display_ecc_public_bb(
std::ostream& os,
Byte_buffer& pd_bb
);

void display_rsa_public(
std::ostream& os,
TPM2B_PUBLIC const& pd
);

void display_ecc_public(
std::ostream& os,
TPM2B_PUBLIC const& pd
);

void display_hmac_public(
std::ostream& os,
TPM2B_PUBLIC const& pd
);

void display_object_attributes(
std::ostream& os,
uint32_t val
);

void display_tpm2b_public(
std::ostream& os,
TPM2B_PUBLIC const& pd
);
