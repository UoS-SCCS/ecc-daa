/*******************************************************************************
* File:        KDF_sha256.h
* Description: TPM KDFa function using SHA256 as the hash algorithm (see
*              TPM Specification Part 1, pg.43 and NIST SP 800-108
*
* Author:      Chris Newton
* Created:     Wednesday 30 May 2018
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

#include <string>
#include "Byte_buffer.h"
#include "Hmac.h"

Byte_buffer KDFa_sha256(
Byte_buffer const& key,		// HMAC key
Byte_buffer const& label,	// label
Byte_buffer const& contextU,
Byte_buffer const& contextV,
uint32_t const size_in_bits,
bool once			// If true only perform 1 iteration 
);

Byte_buffer NIST_SP108_sha256(
Byte_buffer const& key,		// HMAC key
Byte_buffer const& label,	// label, derved from a std::string, no null terminator
Byte_buffer const& context,
uint32_t const size_in_bits
);

Byte_buffer NIST_SP108_sha256_fd(
Byte_buffer const& key,		// HMAC key
Byte_buffer const& fixed_input,
uint32_t const size_in_bits
);
