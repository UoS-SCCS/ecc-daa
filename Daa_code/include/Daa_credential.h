/*******************************************************************************
* File:        Daa_credential.h
* Description: Routines for generating and randomising the DAA credential
*
* Author:      Chris Newton
*
* Created:     Sunday 11 November 2018
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
