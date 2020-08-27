/*******************************************************************************
* File:        Openssl_verify.cpp
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
#include "Openssl_bn_utils.h"
#include "Openssl_ec_utils.h"
#include "Openssl_utils.h"
#include "bnp256_param.h"
#include "Openssl_bnp256.h"
#include "Sha.h"
#include "Credential_issuer.h"

bool openssl_daa_verify(
bool new_daa_signature,
G1_point const& daa_public_key,
Byte_buffer const& str,
Daa_signature const& sig
)
{
    Bn_ctx_ptr ctx =new_bn_ctx();
    Ec_group_ptr ecgrp=new_ec_group("bnp256");
    if (ecgrp.get()==nullptr)
    {
        throw(Openssl_error("openssl_daa_verify: error generating the curve"));
    }
    if (1!=EC_GROUP_check(ecgrp.get(),ctx.get()))
    {
        throw(Openssl_error("openssl_daa_verify: EC_GROUP_check failed"));
    }

    // v
    Byte_buffer const& v=sig[0];
    //w
    Byte_buffer const& w=sig[1];
    // [w]P_1
    G1_point w_p1_bb=ec_generator_mul(ecgrp,w);
    // [v]Q_2
    G1_point v_q2_bb=ec_point_mul(ecgrp,v,daa_public_key);
    // U'
    G1_point tmp_bb=ec_point_invert(ecgrp,v_q2_bb);
    G1_point u_prime_bb=ec_point_add(ecgrp,w_p1_bb,tmp_bb); 
    
    G1_point p1=std::make_pair(bnp256_gX,bnp256_gY);
	Byte_buffer pp=sha256_bb(g1_point_concat(p1)+g1_point_concat(daa_public_key)+g1_point_concat(u_prime_bb)+str);
	Byte_buffer pp_tpm=sha256_bb(pp);

    Byte_buffer const& k=sig[2];
	Byte_buffer v_prime=(!new_daa_signature)?bb_mod(pp_tpm,bnp256_order)
											:bb_mod(sha256_bb(k+pp_tpm),bnp256_order);

    bool verified_OK=(v==v_prime);
 
    return verified_OK;
}


