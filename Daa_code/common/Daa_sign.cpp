/******************************************************************************
* File:        Daa_sign.cpp
* Description: Routines for DAA sign operation
*
* Author:      Chris Newton
*
* Created:     Monday 18 June 2018
*
* (C) Copyright 2018, University of Surrey.
*
******************************************************************************/

#include <sstream>
#include <tuple>
#include "Byte_buffer.h"
#include "Openssl_ec_utils.h"
#include "Tpm_error.h"
#include "Sha.h"
#include "Tpm_defs.h"
#include "Daa_sign.h"

Idv start_daa_validation(
TSS_CONTEXT* tssContext,
TPM_HANDLE daa_key_handle
)
{
	uint16_t counter=0;
	G1_point u_pt;

	Tpm_timer tt;

	Commit_In in;
	Commit_Out out;
	TPM_RC rc=0;

	in.signHandle=daa_key_handle;
	in.P1.point.x.t.size=0;
	in.P1.point.y.t.size=0;
	in.s2.t.size=0;
	in.y2.t.size=0;
	rc = TSS_Execute(tssContext,
		(RESPONSE_PARAMETERS *)&out,
		(COMMAND_PARAMETERS *)&in,
		NULL,
		TPM_CC_Commit,
		TPM_RS_PW, NULL, 0,	
		TPM_RH_NULL, NULL, 0);
	if (rc!=0)
	{
		log_ptr->os() << "start_daa_validation: " << get_tpm_error(rc) << std::endl;
		throw(Tpm_error("start_daa_validation failed"));
	}
	else
	{
		counter=out.counter;
		Byte_buffer u_x(out.E.point.x.t.buffer,out.E.point.x.t.size);
		Byte_buffer u_y(out.E.point.y.t.buffer,out.E.point.y.t.size);
		u_pt=std::make_pair(u_x,u_y);
	}
    tpm_timings.add("TPM2_Commit ()",tt.get_duration());

	return std::make_pair(counter,u_pt);
}

Cdj complete_daa_sign(
TSS_CONTEXT* tssContext,
TPM_HANDLE daa_key_handle,
uint16_t counter,
Byte_buffer const& p
)
{
	TPM_RC rc=0;
	Byte_buffer k;
	Byte_buffer w;

	Tpm_timer tt;

	// First hash the input to get a ticket
	Hash_In h_in;
	Hash_Out h_out;
	h_in.hashAlg=TPM_ALG_SHA256;
	h_in.data.t.size=p.size();
	for (int i=0;i<p.size();++i)
		h_in.data.t.buffer[i]=p[i];
	h_in.hierarchy=TPM_RH_ENDORSEMENT;
	rc = TSS_Execute(tssContext,
			(RESPONSE_PARAMETERS *)&h_out,
			(COMMAND_PARAMETERS *)&h_in,
			NULL,
			TPM_CC_Hash,
			TPM_RH_NULL, NULL, 0);
	if (rc!=0)
	{
		log_ptr->os() << "Hash in complete_daa_sign: " << get_tpm_error(rc) << std::endl;
		throw(Tpm_error("Hash in complete_daa_sign failed"));		
	}
	tpm_timings.add("TPM2_Hash",tt.get_duration());

	tt.reset();

	Sign_In s_in;
	Sign_Out s_out;
	s_in.keyHandle=daa_key_handle;
	s_in.digest=h_out.outHash;
	s_in.inScheme.scheme=TPM_ALG_ECDAA;
	s_in.inScheme.details.ecdaa.count=counter;
	s_in.inScheme.details.ecdaa.hashAlg=TPM_ALG_SHA256;
	s_in.validation=h_out.validation;
	rc = TSS_Execute(tssContext,
			(RESPONSE_PARAMETERS *)&s_out,
			(COMMAND_PARAMETERS *)&s_in,
			NULL,
			TPM_CC_Sign,
			TPM_RS_PW, NULL, 0,
			TPM_RH_NULL, NULL, 0);
	if (rc!=0)
	{
		log_ptr->os() << "Sign in complete_daa_sign: " << get_tpm_error(rc) << std::endl;
		throw(Tpm_error("Sign in complete_daa_sign failed"));		
	}
	else
	{
		k=Byte_buffer(s_out.signature.signature.ecdaa.signatureR.t.buffer,s_out.signature.signature.ecdaa.signatureR.t.size);
		w=Byte_buffer(s_out.signature.signature.ecdaa.signatureS.t.buffer,s_out.signature.signature.ecdaa.signatureS.t.size);
	}
	tpm_timings.add("TPM2_Sign (ECDAA)",tt.get_duration());

	return std::make_pair(k,w);
}
