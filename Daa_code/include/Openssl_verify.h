/*******************************************************************************
* File:        Openssl_verify.h
* Description: Openssl functions to verify DAA signatures
*
* Author:      Chris Newton
* Created:     Tuesday 1 AUgust 2018
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

