/*******************************************************************************
* File:        Credential_issuer.h
* Description: Issuer structure used to for the DAA protocol
*
* Author:      Chris Newton
*
* Created:     Sunday 12 August 2018
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
#include <array>
#include "Tss_includes.h"
#include "Byte_buffer.h"
#include "Get_random_bytes.h"
#include "Openssl_ec_utils.h"
#include "Openssl_aes.h"
#include "Openssl_verify.h"
#include "Make_credential.h"
#include "G2_utils.h"
#include "Issuer_public_keys.h"
#include "Daa_credential.h"


class Daa_applicant_data
{
public:
	Byte_buffer ek;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
	TPM2B_PUBLIC daa_pd;
#pragma GCC diagnostic pop
	Byte_buffer current_k_cal;
};


class Credential_issuer{
public:
	Credential_issuer();
	void set_ek_public_key(Byte_buffer const& ek_pk){appl_.ek=ek_pk;}	
	TPM_RC set_daa_public_data(Byte_buffer const& daa_pd);
	Credential_data make_credential_data();
	bool check_daa_signature(bool new_daa_signature, Byte_buffer const& c_key, Daa_signature const& sig);
	Issuer_public_keys get_public_keys() const {return pk_;}	
	std::pair<Credential_data, Byte_buffer> make_full_credential();

private:
	// Secret keys x and y
	Byte_buffer sk_x_;
	Byte_buffer sk_y_;
	// Public keys X and Y
//	G2_point pk_x_;
//	G2_point pk_y_;
    // Public keys (X,Y)
    Issuer_public_keys pk_;

    Random_byte_generator rbg_;
	size_t credential_key_bytes_;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
	Daa_applicant_data appl_;
#pragma GCC diagnostic pop
	std::pair<Daa_credential,Daa_credential_signature> make_daa_credential();
};
