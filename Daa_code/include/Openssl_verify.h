/***************************************************************************
* File:        Openssl_verify.h
* Description: Openssl functions to verify DAA signatures
*
* Author:      Chris Newton
* Created:     Tuesday 1 AUgust 2018
*
* (C) Copyright 2018, University of Surrey.
*
****************************************************************************/

#pragma once 

#include <cstdint>
#include <string>
#include <array>
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

using Daa_signature=std::array<Byte_buffer,3>;

bool openssl_daa_verify(
bool new_daa_signature,
G1_point const& daa_public_key,
Byte_buffer const& str,
Daa_signature const& sig
);

