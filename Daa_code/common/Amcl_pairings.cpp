/*******************************************************************************
* File:        Amcl_pairings.cpp
* Description: Routines for checking pairings using AMCL
*
* Author:      Chris Newton
* Created:     Wednesday 28 November 2018
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


#include "Tpm_defs.h"
#include "G2_utils.h"
#include "Amcl_utils.h"
#include "Daa_credential.h"
#include "Amcl_pairings.h"

Issuer_public_keys amcl_calculate_public_keys(Issuer_private_keys const& pks)
{
    using namespace FP256BN;
	using namespace FP256BN_BIG;

	// Generator for G2 - MUST use the generator provided and not the one
	// from the ISO example!!
    ECP2 p2;
	ECP2_generator(&p2);

	Byte_buffer sk_x=pks.first;;
    sk_x.pad_left(component_size);
	Byte_buffer sk_y=pks.second;
    sk_y.pad_left(component_size);

    BIG x,y;
    bb_to_big(sk_x,x);
    bb_to_big(sk_y,y);

    ECP2 ecp2_x,ecp2_y;

	ECP2_copy(&ecp2_x,&p2);
    ECP2_mul(&ecp2_x,x);
    G2_point pk_x=g2_point_from_bb(ecp2_to_bb(&ecp2_x));

	
	ECP2_copy(&ecp2_y,&p2);
    ECP2_mul(&ecp2_y,y);
    G2_point pk_y=g2_point_from_bb(ecp2_to_bb(&ecp2_y));

	if (log_ptr->debug_level()>1)
	{
		log_ptr->os() << "  P2: " << ecp2_to_bb(&p2).to_hex_string() << '\n';
		log_ptr->os() << "pk_x: " << ecp2_to_bb(&ecp2_x).to_hex_string() << '\n';
		log_ptr->os() << "pk_y: " << ecp2_to_bb(&ecp2_y).to_hex_string() << '\n';
	}

	return std::make_pair(pk_x,pk_y);
}

bool check_daa_pairings(
Daa_credential const& cre,
Issuer_public_keys const& issuer_keys
)
{
	bool pairings_ok=true;

    using namespace FP256BN;
	using namespace FP256BN_BIG;

	// Generator for G2 - MUST use the generator provided and not the one
	// from the ISO example!!
    ECP2 p2;
	ECP2_generator(&p2);

    ECP2 ecp2_x,ecp2_y;
	bb_to_ecp2(g2_point_concat(issuer_keys.first),&ecp2_x);
	bb_to_ecp2(g2_point_concat(issuer_keys.second),&ecp2_y);

    ECP g1_0,g1_1,g1_2,g1_3;
    g1_point_to_ecp(cre[0],&g1_0);
	g1_point_to_ecp(cre[1],&g1_1);
	g1_point_to_ecp(cre[2],&g1_2);
	g1_point_to_ecp(cre[3],&g1_3);

	FP12 pair_lhs,pair_rhs;

	PAIR_ate(&pair_lhs,&ecp2_y,&g1_0);
	PAIR_fexp(&pair_lhs);

	PAIR_ate(&pair_rhs,&p2,&g1_1);
	PAIR_fexp(&pair_rhs);

	if(!FP12_equals(&pair_lhs,&pair_rhs))
	{
		pairings_ok=false;
		if (log_ptr->debug_level()>0)
		{
			log_ptr->os() << "Pairing 1 failed\n";
		}
	}

	ECP_add(&g1_3,&g1_0);
    if (log_ptr->debug_level()>0)
    {
        log_ptr->os() << "cre[0]+cre[3]: " << ecp_to_bb(&g1_3).to_hex_string() << std::endl;
    }

	PAIR_ate(&pair_lhs,&ecp2_x,&g1_3);
	PAIR_fexp(&pair_lhs);

	PAIR_ate(&pair_rhs,&p2,&g1_2);
	PAIR_fexp(&pair_rhs);

	if(!FP12_equals(&pair_lhs,&pair_rhs))
	{
		pairings_ok=false;
		if (log_ptr->debug_level()>0)
		{
			log_ptr->os() << "Pairing 2 failed\n";
		}
	}

	return pairings_ok;
}
