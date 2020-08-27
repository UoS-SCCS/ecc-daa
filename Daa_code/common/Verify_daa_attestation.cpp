/*******************************************************************************
* File:        Verify_daa_attestation.cpp
* Description: Function to verify the signature on attestation data
*
* Author:      Chris Newton
* Created:     Wednesday 2 AUgust 2018
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
#include "Openssl_utils.h"
#include "Openssl_bn_utils.h"
#include "Openssl_ec_utils.h"
#include "bnp256_param.h"
#include "Openssl_bnp256.h"
#include "Verify_daa_attestation.h"
#include "Model_hashes.h"
#include "Sha.h"
#include "Tpm_error.h"
#include "Tpm_defs.h"
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
)
{

    bool verified_OK=false;

    try
    {
        Byte_buffer hash1=sha256_bb(c+attest_hash);

        Bn_ctx_ptr ctx=new_bn_ctx();
        Ec_group_ptr ecgrp=new_ec_group("bnp256");
        if (ecgrp.get()==nullptr)
        {
            throw(Tpm_error("Error generating the ECC curve"));
        }
        if (1!=EC_GROUP_check(ecgrp.get(),ctx.get()))
        {
            throw(Tpm_error("ECC curve check failed"));
        }

        // h_2
        Byte_buffer hash2=(!new_daa_signature)?nt:bb_mod(sha256_bb(nt+hash1),bnp256_order);

        G1_point l_prime_bb;
        G1_point e_prime_bb;
        G1_point tmp_bb;
        if (pt_j.first.size()>0)   // Basename set, so calculate L'
        {
            // [s]J
            G1_point s_j_bb=ec_point_mul(ecgrp,sig_s,pt_j);
            // [h_2]K
            G1_point h2_k_bb=ec_point_mul(ecgrp,hash2,pts[0]);
            // L'
            tmp_bb=ec_point_invert(ecgrp,h2_k_bb);
            l_prime_bb=ec_point_add(ecgrp,s_j_bb,tmp_bb); 
        }
        // [s]S
        G1_point s_pt_s_bb=ec_point_mul(ecgrp,sig_s,r_cre1[1]);
        // [h_2]W
        G1_point h2_pt_w_bb=ec_point_mul(ecgrp,hash2,r_cre1[3]);
        // E'
        tmp_bb=ec_point_invert(ecgrp,h2_pt_w_bb);
        e_prime_bb=ec_point_add(ecgrp,s_pt_s_bb,tmp_bb); 

        if (log_ptr->debug_level()>0)
        {
            log_ptr->os() << "verify_daa_attastation: calculated points: \nL'_x :" << l_prime_bb.first.to_hex_string()
                          << "\nL'_y: " << l_prime_bb.second.to_hex_string() << "\nE'_x: "
                          << e_prime_bb.first.to_hex_string() << "\nE'_y: " << e_prime_bb.second.to_hex_string()
                          << std::endl;
        }


        Byte_buffer v_c=sign_c(label,r_cre1,pt_j,pts[0],l_prime_bb,e_prime_bb);

        verified_OK=(v_c==c);

    }
    catch (Tpm_error &e)
	{
	    std::cerr << e.what() << '\n';
	}
	catch (...)
	{
		std::cerr << "Failed - uncaught exception";
	}

    return verified_OK;
}


