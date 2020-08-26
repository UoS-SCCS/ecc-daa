/***************************************************************************
* File:        Openssl_rsa_encrypt.h
* Description: RSA encryption using public key and a label (for TPM test)
*
* Author:      Chris Newton
* Created:     Wednesday 13 June 2018
*
* (C) Copyright 2018, University of Surrey.
*
****************************************************************************/

#pragma once

# include <openssl/rsa.h>
#include "Number_conversions.h"
#include "Byte_buffer.h"


const size_t rsa_key_size=2048;

Byte_buffer encrypt_rsa2048(
Byte_buffer const& label,        
Byte_buffer const& in,
Byte_buffer const& modulus_bb,
Byte_buffer const& exponent_bb
);

