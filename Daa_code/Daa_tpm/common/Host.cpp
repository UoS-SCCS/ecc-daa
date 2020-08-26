/***************************************************************************
* File:        Host.cpp
* Description: Host routines used to test the Tpm_daa class
*
* Author:      Chris Newton
*
* Created:     Thursday 12 July 2018
*
* (C) Copyright 2018, University of Surrey.
*
****************************************************************************/

#include <iostream>
#include <string>
#include "Tss_includes.h"
#include "Tpm_error.h"
#include "Tpm_daa.h"
#include "Byte_buffer.h"
#include "G1_utils.h"
#include "Make_credential.h"
#include "Model_hashes.h"
#include "Host.h"

TPM_RC get_credential_key(Tpm_daa& tpm,
Credential_data const& cd,
Byte_buffer& ck
)
{
	TPM_RC rc=tpm.activate_credential(cd.second,cd.first,ck);
	if (rc!=0)
	{
		std::cerr << "activate_credential returned: " << tpm.get_last_error() << '\n';
	}

	return rc;
}

bool verify_daa_credential_signature(
G1_point const& p1,
G1_point const& daa_key,
Daa_credential const& cre,
Daa_credential_signature const& sig
)
{
    bool signature_ok=false;
    try
    {
        Bn_ctx_ptr ctx =new_bn_ctx();
        Ec_group_ptr ecgrp=new_ec_group("bnp256"); // Curve name ignored for the moment
        if (ecgrp.get()==nullptr)
        {
            throw(Tpm_error("verify_daa_credential_signature: error generating the curve"));
        }

        G1_point const& cre_b=cre[1];
        G1_point const& cre_d=cre[3];

        Byte_buffer const& u=sig[0];
        Byte_buffer const& j=sig[1];
        // [j]P_1
        G1_point j_p1_bb=ec_generator_mul(ecgrp,j);
        if (!point_is_on_curve(ecgrp,j_p1_bb))
        {
            throw(Tpm_error("verify_daa_credential_signature: [j]P_1 is not on the curve"));
        }
        // [j]Q
        G1_point j_q2_bb=ec_point_mul(ecgrp,j,daa_key);
        if (!point_is_on_curve(ecgrp,j_q2_bb))
        {
            throw(Tpm_error("verify_daa_credential_signature: [j]Q is not on the curve"));
        }
        // [u]B
        G1_point u_b=ec_point_mul(ecgrp,u,cre_b);
        if (!point_is_on_curve(ecgrp,u_b))
        {
            throw(Tpm_error("verify_daa_credential_signature: [u]B is not on the curve"));
        }
        // [u]D
        G1_point u_d=ec_point_mul(ecgrp,u,cre_d);
        if (!point_is_on_curve(ecgrp,u_d))
        {
            throw(Tpm_error("verify_daa_credential_signature: [u]D is not on the curve"));
        }
        // R_B'
        G1_point tmp_bb=ec_point_invert(ecgrp,u_b);
        G1_point r_b_prime=ec_point_add(ecgrp,j_p1_bb,tmp_bb); 
        if (!point_is_on_curve(ecgrp,r_b_prime))
        {
            throw(Tpm_error("verify_daa_credential_signature: R_B' is not on the curve"));
        }
        // R_D'
        tmp_bb=ec_point_invert(ecgrp,u_d);
        G1_point r_d_prime=ec_point_add(ecgrp,j_q2_bb,tmp_bb); 
        if (!point_is_on_curve(ecgrp,r_d_prime))
        {
            throw(Tpm_error("verify_daa_credential_signature: R_D' is not on the curve"));
        }

        auto u_prime=issuer_u(p1,daa_key,cre,r_b_prime,r_d_prime);

        signature_ok=(u==u_prime);
    }
	catch (Tpm_error &e)
	{
		std::cerr << e.what() << '\n';
	}
	catch (...)
	{
		std::cerr << "Failed - uncaught exception\n";
	}

	return signature_ok;	
}
