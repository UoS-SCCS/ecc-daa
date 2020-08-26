/******************************************************************************
* File:        Daa_credential.h
* Description: Routines for generating and randomising the DAA credential
*
* Author:      Chris Newton
*
* Created:     Sunday 11 November 2018
*
* (C) Copyright 2018, University of Surrey.
*
******************************************************************************/

#pragma once

#include <vector>
#include <array>
#include "Byte_buffer.h"
#include "Get_random_bytes.h"
#include "G1_utils.h"

using Daa_credential=std::array<G1_point,4>;
using Daa_credential_signature=std::array<Byte_buffer,2>;

std::pair<Daa_credential,Daa_credential_signature> generate_and_sign_daa_credential(G1_point const& daa_key,Random_byte_generator& rbg);

Daa_credential randomise_daa_credential(Daa_credential const& dc,Random_byte_generator& rbg);

Byte_buffer daa_credential_concat(Daa_credential const& cre);

Byte_buffer serialise_daa_credential(Daa_credential const& dc);
Daa_credential deserialise_daa_credential(Byte_buffer const& bb);
Byte_buffer serialise_daa_credential_signature(Daa_credential_signature const& dc);
Daa_credential_signature deserialise_daa_credential_signature(Byte_buffer const& bb);
