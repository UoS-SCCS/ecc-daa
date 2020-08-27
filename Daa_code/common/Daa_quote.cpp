/*******************************************************************************
* File:        Daa_quote.cpp
* Description: DAA quote - routine for TPM2_Quote
*
* Author:      Chris Newton
*
* Created:     saturday 15 September 2018
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
#include <chrono>
#include <cstring>
#include "Tpm_defs.h"
#include "Daa_quote.h"

Quote_data complete_daa_quote(
TSS_CONTEXT* tss_context,
TPM_HANDLE daa_key_handle,
TPML_PCR_SELECTION const& pcr_sel,
uint16_t counter,
Byte_buffer const& qd
)
{
	Quote_data quote;

	Tpm_timer tt;

	Quote_In quote_in;
	Quote_Out quote_out;
	
	quote_in.signHandle=daa_key_handle;
	quote_in.inScheme.scheme=TPM_ALG_ECDAA;
	quote_in.inScheme.details.ecdaa.count=counter;
	quote_in.inScheme.details.ecdaa.hashAlg=TPM_ALG_SHA256;
	quote_in.qualifyingData.t.size=qd.size();
	memcpy(quote_in.qualifyingData.t.buffer,&qd[0],qd.size());
    quote_in.PCRselect=pcr_sel;
 
	TPM_RC rc = TSS_Execute(tss_context,
		(RESPONSE_PARAMETERS *)&quote_out,
		(COMMAND_PARAMETERS *)&quote_in,
		NULL,
		TPM_CC_Quote,
		TPM_RS_PW, NULL, 0,
		TPM_RH_NULL, NULL, 0);
 	if (rc!=0)
	{
        log_ptr->os() << "complete_daa_quote: " << get_tpm_error(rc) << '\n';
        throw(Tpm_error("complete_daa_Quote: Quote failed"));
	}        
	quote[0]=Byte_buffer(quote_out.quoted.t.attestationData,
						 quote_out.quoted.t.size);
	
	TPMS_SIGNATURE_ECDSA& sig=quote_out.signature.signature.ecdaa;
	quote[1]=Byte_buffer(sig.signatureR.t.buffer,sig.signatureR.t.size);
	quote[2]=Byte_buffer(sig.signatureS.t.buffer,sig.signatureS.t.size);

	tpm_timings.add("TPM2_Quote", tt.get_duration());

   	return quote;
}
