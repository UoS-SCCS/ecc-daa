/***************************************************************************
* File:        Openssl_verify.cpp
* Description: Openssl functions to verify DAA signatures
*
* Author:      Chris Newton
* Created:     Tuesday 1 AUgust 2018
*
* (C) Copyright 2018, University of Surrey.
*
****************************************************************************/

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


