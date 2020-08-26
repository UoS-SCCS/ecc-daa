/***************************************************************************
* File:        Host.h
* Description: Host routines used to test the Tpm_daa class
*
* Author:      Chris Newton
*
* Created:     Thursday 12 July 2018
*
* (C) Copyright 2018, University of Surrey.
*
****************************************************************************/

#pragma once

#include <iostream>
#include <string>
#include <array>
#include <tss2/tss.h>
#include "Byte_buffer.h"
#include "Make_credential.h"
#include "Openssl_ec_utils.h"
#include "Openssl_bnp256.h"
#include "Sha.h"
#include "bnp256_param.h"
#include "Credential_issuer.h"
#include "Tpm_daa.h"

TPM_RC get_credential_key(
Tpm_daa& tpm,
Credential_data const& cd,
Byte_buffer& ck
);

bool verify_daa_credential_signature(
G1_point const& p1,
G1_point const& daa_key,
Daa_credential const& cre,
Daa_credential_signature const& sig
);
