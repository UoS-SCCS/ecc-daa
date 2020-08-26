/***************************************************************************
* File:        KDF_sha256.h
* Description: TPM KDFa function using SHA256 as the hash algorithm (see
*              TPM Specification 1.38, Part 1, pg.43 and NIST SP 800-108)
*			   also TPM KDFe function using SHA256 (see TPM specification 1.38,
			   Part 1, pg. 45 and NIST SP 800 56C)
*
* Author:      Chris Newton
* Created:     Wednesday 30 May 2018, KDFe added 11 July 2020
*
* (C) Copyright 2018, University of Surrey.
*
****************************************************************************/

#pragma once

#include <string>
#include "Byte_buffer.h"
#include "Hmac.h"
#include "Sha.h"

Byte_buffer KDFa_sha256(
Byte_buffer const& key,		// HMAC key
Byte_buffer const& label,	// label
Byte_buffer const& contextU,
Byte_buffer const& contextV,
uint32_t const size_in_bits,
bool once			// If true only perform 1 iteration 
);

Byte_buffer NIST_SP108_sha256_fd(
Byte_buffer const& key,		// HMAC key
Byte_buffer const& fixed_input,
uint32_t const size_in_bits
);

Byte_buffer NIST_SP56C_sha256_fd(
Byte_buffer const& key,		// HMAC key
Byte_buffer const& fixed_input,
uint32_t const size_in_bits
);

