/*******************************************************************************
* File:        Credential_issuer.cpp
* Description: Implementation of the Credential_issuer structure
*
* Author:      Chris Newton
*
* Created:     Sunday 12 August 2018
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


#include <iostream>
#include <string>
#include <vector>
#include "Byte_buffer.h"
#include "Marshal_public_data.h"
#include "Get_random_bytes.h"
#include "Make_credential.h"
#include "Daa_credential.h"
#include "Credential_issuer.h"
#include "Mechanism_4_data.h"
#include "Tpm_utils.h"
#include "Tpm_error.h"
#include "Openssl_verify.h"
#include "Daa_credential.h"
#include "Model_hashes.h"
#include "Amcl_pairings.h"
#include "Tpm_defs.h"

Credential_issuer::Credential_issuer() : sk_x_(iso_sk_x), sk_y_(iso_sk_y)
{
    credential_key_bytes_=aes_key_bytes;
 
	pk_=amcl_calculate_public_keys(std::make_pair(sk_x_,sk_y_));
}

TPM_RC Credential_issuer::set_daa_public_data(Byte_buffer const& daa_pd)
{
	Byte_buffer daad=daa_pd;
	return unmarshal_public_data_B(daad,&appl_.daa_pd);
}

Credential_data Credential_issuer::make_credential_data()
{
    appl_.current_k_cal = rbg_(credential_key_bytes_);

	return make_credential_issuer(appl_.ek,appl_.daa_pd,appl_.current_k_cal,rbg_);
}

bool Credential_issuer::check_daa_signature(bool new_daa_signature,
							Byte_buffer const& c_key, Daa_signature const& sig)
{
    if (log_ptr->debug_level()>0)
    {
        log_ptr->os() << "check_daa_signature: \nc_key: " << c_key.to_hex_string() << std::endl;
    }
    
    if (!(c_key==appl_.current_k_cal))
	{
		log_ptr->os() << "check_daa_signature: incorrect credential key" << std::endl;
		return false;
	}

    if (log_ptr->debug_level()>0)
    {
        log_ptr->os() << "check_daa_signature: \nsig[0]: " << sig[0].to_hex_string() << '\n'
                      << "sig[1]: " << sig[1].to_hex_string() << '\n'
                      << "sig[2]: " << sig[2].to_hex_string() << std::endl;
    }

	Byte_buffer str=host_str(pk_.first,pk_.second,appl_.current_k_cal,appl_.ek);

	G1_point daa_public_key=get_daa_key_from_public_data(appl_.daa_pd);

	bool verified_ok=openssl_daa_verify(new_daa_signature,daa_public_key,str,sig);

    return verified_ok;
}

std::pair<Daa_credential,Daa_credential_signature> Credential_issuer::make_daa_credential()
{
	G1_point daa_public_key=get_daa_key_from_public_data(appl_.daa_pd);

    size_t random_bytes=daa_public_key.first.size();

    Ec_group_ptr ecgrp=new_ec_group("bnp256"); // Curve name ignored at the moment
    if (ecgrp==NULL)
    {
        throw(Tpm_error("Error generating the BN_P256 curve"));
    }

    if (!point_is_on_curve(ecgrp,daa_public_key))
    {
        throw(Tpm_error("DAA key is not on the curve"));
    }

    Byte_buffer x=sk_x_;
    Byte_buffer y=sk_y_;

    Daa_credential cre;
    G1_point p1=std::make_pair(bnp256_gX,bnp256_gY); // Generator

    Bn_ctx_ptr ctx=new_bn_ctx();
    Bn_ptr bn_n=new_bn();
    BN_bin2bn(&bnp256_order[0],bnp256_order.size(),bn_n.get());
    Bn_ptr bn_x=new_bn();
    BN_bin2bn(&x[0],x.size(),bn_x.get());
    Bn_ptr bn_y=new_bn();
    BN_bin2bn(&y[0],y.size(),bn_y.get());
    Bn_ptr bn_r=new_bn();
    Bn_ptr bn_ry=new_bn();

    Byte_buffer r;

    Ec_point_ptr pt_qs=new_ec_point(ecgrp);
    bb2point(ecgrp,daa_public_key,pt_qs);
    Ec_point_ptr pt_a=new_ec_point(ecgrp);
    Ec_point_ptr pt_b=new_ec_point(ecgrp);
    Ec_point_ptr pt_c=new_ec_point(ecgrp);
    Ec_point_ptr pt_d=new_ec_point(ecgrp);
    Ec_point_ptr pt_tmp=new_ec_point(ecgrp);

    bool cre_ok=false;
	while (!cre_ok)
	{
        cre_ok=true;
        try
        {  
            r=rbg_(random_bytes);
            BN_bin2bn(&r[0],r.size(),bn_r.get());
            // A=[r]P_1
            if (1!=EC_POINT_mul(ecgrp.get(),pt_a.get(),bn_r.get(),NULL,NULL,ctx.get()))
            {
                throw(Openssl_error("EC multiplication failed: [r]P_1"));
            }
            // B=[y]A
          	if (1!=EC_POINT_mul(ecgrp.get(),pt_b.get(),NULL,pt_a.get(),bn_y.get(),ctx.get()))
	        {
                throw(Openssl_error("EC multiplication failed: [y]A"));           
            }
            if (1!=BN_mod_mul(bn_ry.get(),bn_r.get(),bn_y.get(),bn_n.get(),ctx.get()))
            {
                throw(Openssl_error("Modular multiplication failed ry"));
            }
            // D=[ry]Q_s
          	if (1!=EC_POINT_mul(ecgrp.get(),pt_d.get(),NULL,pt_qs.get(),bn_ry.get(),ctx.get()))
	        {
                throw(Openssl_error("EC multiplication failed: [ry]Q_s"));           
            }
            // tmp=A+D
           	if (1!=EC_POINT_add(ecgrp.get(),pt_tmp.get(),pt_a.get(),pt_d.get(),ctx.get()))
            {
                throw(Openssl_error("ec_point_add failed A+D"));
            }
            // C=[x]tmp
          	if (1!=EC_POINT_mul(ecgrp.get(),pt_c.get(),NULL,pt_tmp.get(),bn_x.get(),ctx.get()))
	        {
                throw(Openssl_error("EC multiplication failed: [ry]Q_s"));           
            }

            cre[0]=point2bb(ecgrp,pt_a);
            cre[1]=point2bb(ecgrp,pt_b);
            cre[2]=point2bb(ecgrp,pt_c);
            cre[3]=point2bb(ecgrp,pt_d);
        }
        catch(Openssl_error const& e)
        {
            if (log_ptr->debug_level()>0)
            {
                 log_ptr->os() <<"Credential calculation failed: " << e.what() << ", so trying again\n";
            }
            cre_ok=false; // a calculation failed, so try again
        }
	}
    
    Daa_credential_signature sig;

    Byte_buffer nl=bb_mod(rbg_(random_bytes),bnp256_order);
    G1_point r_b=ec_point_mul(ecgrp,nl,p1); // R_B
    G1_point r_d=ec_point_mul(ecgrp,nl,daa_public_key); // R_D
    
    Byte_buffer ry;
    ry=bb_mod_mul(r,y,bnp256_order);
    
    sig[0]=issuer_u(p1,daa_public_key,cre,r_b,r_d);
    sig[1]=bb_signature_calc(nl,ry,sig[0],bnp256_order);

    return std::make_pair(cre,sig);
}

std::pair<Credential_data, Byte_buffer> Credential_issuer::make_full_credential()
{
	Credential_data cd=make_credential_data();

	auto daa_cre=make_daa_credential();
	std::vector<Byte_buffer> tmp_bv(2);
	tmp_bv[0]=serialise_daa_credential(daa_cre.first);
	tmp_bv[1]=serialise_daa_credential_signature(daa_cre.second);
	Byte_buffer cre=serialise_byte_buffers(tmp_bv);

 	Byte_buffer initial_iv(aes_block_size,0);
    Byte_buffer c_hat=ossl_encrypt("AES-128-CTR",cre,appl_.current_k_cal,initial_iv);

	return std::make_pair(cd,c_hat);
}

