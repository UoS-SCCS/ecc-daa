/***************************************************************************
* File:        Verify_daa_attestation.h
* Description: Function to verify the signature on attestation data
*
* Author:      Chris Newton
* Created:     Wednesday 2 AUgust 2018
*
* (C) Copyright 2018, University of Surrey.
*
****************************************************************************/

#pragma once 

#include <cstdint>
#include <string>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include "Byte_buffer.h"
#include "Openssl_utils.h"
#include "Tpm2_commit.h"
#include "Daa_certify.h"

bool verify_daa_attestation(
bool new_daa_signature,
Byte_buffer const& label,
Point_set  const& r_cre1,
G1_point const& pt_j,
Commit_points const& pts,
Byte_buffer const& c,
Byte_buffer const& attest_hash,
Byte_buffer const& nt,
Byte_buffer const& sig_s
);


