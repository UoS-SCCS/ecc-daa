/*******************************************************************************
* File:        Daa_credential.cpp
* Description: Routines for generating and randomising the DAA credential
*
* Author:      Chris Newton
*
* Created:     Sunday 11 November 2018
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


#include "Tpm_error.h"
#include "Mechanism_4_data.h"
#include "Get_random_bytes.h"
#include "Openssl_ec_utils.h"
#include "Openssl_utils.h"
#include "Sha.h"
#include "Daa_credential.h"
#include "bnp256_param.h"


std::pair<Daa_credential,Daa_credential_signature> generate_and_sign_daa_credential(G1_point const& daa_key, Random_byte_generator& rbg)
{
    size_t random_bytes=daa_key.first.size();

    Ec_group_ptr ecgrp=new_ec_group("bnp256");
    if (ecgrp==NULL)
    {
        throw(Tpm_error("Error generating the BN_P256 curve"));
    }

    if (!point_is_on_curve(ecgrp,daa_key))
    {
        throw(Tpm_error("DAA key is not on the curve"));
    }


    Byte_buffer x=iso_sk_x;
    Byte_buffer y=iso_sk_y;

    Daa_credential cre;
    Byte_buffer ry;
    G1_point p1= std::make_pair(bnp256_gX,bnp256_gY); // Generator
    bool cre_ok=false;
    while (!cre_ok)
    {
        cre_ok=true;
        try
        {
            Byte_buffer r=bb_mod(rbg(random_bytes),bnp256_order);
            cre[0]=ec_point_mul(ecgrp,r,p1);        // A
            cre[1]=ec_point_mul(ecgrp,y,cre[0]);    // B
            ry=bb_mod_mul(r,y,bnp256_order);
            cre[3]=ec_point_mul(ecgrp,ry,daa_key);  // D
            cre[2]=ec_point_mul(ecgrp,x,ec_point_add(ecgrp,cre[0],cre[3])); // C
        }
        catch(Openssl_error const& e)
        {
            std::cout << "Credential calculation failed: " << e.what() << ", so trying again\n";
            cre_ok=false;   // A calculation failed, so try again
        }        
    }

    Daa_credential_signature sig;

    Byte_buffer nl=bb_mod(rbg(random_bytes),bnp256_order);
    G1_point r_b=ec_point_mul(ecgrp,nl,p1); // R_B
    G1_point r_d=ec_point_mul(ecgrp,nl,daa_key); // R_D

    Byte_buffer h_str=g1_point_concat(p1)+g1_point_concat(daa_key)+g1_point_concat(r_b)+g1_point_concat(r_d);
    sig[0]=bb_mod(sha256_bb(h_str),bnp256_order);
    sig[1]=bb_signature_calc(nl,ry,sig[0],bnp256_order);

    return std::make_pair(cre,sig);
}

Daa_credential randomise_daa_credential(Daa_credential const& dc, Random_byte_generator& rbg)
{
    size_t nonce_bytes=dc[0].first.size();

    Ec_group_ptr ecgrp=new_ec_group("bnp256"); // Name ignored at the moment
    if (ecgrp==NULL)
    {
        throw(Tpm_error("Error generating the BN_P256 curve"));
    }

    Daa_credential r_cre;
    bool cre_ok=false;
    while (!cre_ok)
    {
        cre_ok=true;
        Byte_buffer l=bb_mod(rbg(nonce_bytes),bnp256_order);
        for (int i=0;i<dc.size();++i)
        {
            try
            {
                r_cre[i]=ec_point_mul(ecgrp,l,dc[i]); // 0-R, 1-S, 2-T, 3-W
            }
            catch(Openssl_error const& e)
            {
                cre_ok=false;   // a calculation failed, so try again 
                break;
            }
        }
    }

    return r_cre;
}

Byte_buffer daa_credential_concat(Daa_credential const& cre)
{
    Byte_buffer tmp_bb;
    for (int i=0;i<4;++i)
    {
        tmp_bb+=g1_point_concat(cre[i]);
    }
    return tmp_bb;
}

Byte_buffer serialise_daa_credential(Daa_credential const& dc)
{
    std::vector<Byte_buffer> tmp_bv(dc.size());
    for (int i=0;i<dc.size();++i)
    {
        tmp_bv[i]=g1_point_serialise(dc[i]);
    }
    return serialise_byte_buffers(tmp_bv);
}

Daa_credential deserialise_daa_credential(Byte_buffer const& bb)
{
    Daa_credential dc;
    auto tmp_spv=deserialise_byte_buffers(bb);
    if (tmp_spv.size()!=dc.size())
    {
        throw(Tpm_error("Deserialisation of DAA credential failed"));
    }
    
    for (int i=0;i<dc.size();++i)
    {
        dc[i]=g1_point_deserialise(tmp_spv[i]);
    }
    return dc;
}

Byte_buffer serialise_daa_credential_signature(Daa_credential_signature const& ds)
{
    std::vector<Byte_buffer> tmp_bv(ds.size());
    for (int i=0;i<ds.size();++i)
    {
        tmp_bv[i]=ds[i];
    }
    return serialise_byte_buffers(tmp_bv);
}

Daa_credential_signature deserialise_daa_credential_signature(Byte_buffer const& bb)
{
    Daa_credential_signature ds;
    auto tmp_spv=deserialise_byte_buffers(bb);
    if (tmp_spv.size()!=ds.size())
    {
        throw(Tpm_error("Deserialisation of DAA signature failed"));
    }
    
    for (int i=0;i<ds.size();++i)
    {
        ds[i]=tmp_spv[i];
    }
    return ds;
}
