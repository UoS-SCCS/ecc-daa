/***************************************************************************
* File:        Credential_issuer.h
* Description: Issuer structure used to for the DAA protocol
*
* Author:      Chris Newton
*
* Created:     Sunday 12 August 2018
*
* (C) Copyright 2018, University of Surrey.
*
****************************************************************************/

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
