/*******************************************************************************
* File:        Daa_certify.cpp
* Description: DAA join - test routines from Join protocol
*
* Author:      Chris Newton
*
* Created:     Monday 18 June 2018
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


#include <sstream>
#include <chrono>
#include <cstring>
#include "Tss_includes.h"
#include "Tpm_defs.h"
#include "Daa_certify.h"

Certify_data complete_daa_certify(
TSS_CONTEXT* tss_context,
TPM_HANDLE daa_key_handle,
TPM_HANDLE cert_handle,
uint16_t counter,
Byte_buffer const& qd
)
{
	Certify_data cert;

	Tpm_timer tt;

	Certify_In cert_in;
	Certify_Out cert_out;

	cert_in.signHandle=daa_key_handle;
	cert_in.objectHandle=cert_handle;
	cert_in.inScheme.scheme=TPM_ALG_ECDAA;
	cert_in.inScheme.details.ecdaa.count=counter;
	cert_in.inScheme.details.ecdaa.hashAlg=TPM_ALG_SHA256;
	cert_in.qualifyingData.t.size=qd.size();
	memcpy(cert_in.qualifyingData.t.buffer,&qd[0],qd.size());

	TPM_RC rc = TSS_Execute(tss_context,
		(RESPONSE_PARAMETERS *)&cert_out,
		(COMMAND_PARAMETERS *)&cert_in,
		NULL,
		TPM_CC_Certify,
		TPM_RS_PW, NULL, 0,
		TPM_RS_PW, NULL, 0,
		TPM_RH_NULL, NULL, 0);
	if (rc!=0)
	{
		log_ptr->os() << "complete_daa_certify: " << get_tpm_error(rc) << std::endl;
		throw(Tpm_error("complete_daa_certify: certify failed"));
	}        
	cert[0]=Byte_buffer(cert_out.certifyInfo.t.attestationData,
						cert_out.certifyInfo.t.size);

	TPMS_SIGNATURE_ECDSA& sig=cert_out.signature.signature.ecdaa;
	cert[1]=Byte_buffer(sig.signatureR.t.buffer,sig.signatureR.t.size);
	cert[2]=Byte_buffer(sig.signatureS.t.buffer,sig.signatureS.t.size);

	tpm_timings.add("TPM2_Certify", tt.get_duration());

	return cert;
}
