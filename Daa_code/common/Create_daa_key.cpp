/*******************************************************************************
* File:        create_daa_key.cpp
* Description: Create a DAA key
*
* Author:      Chris Newton
*
* Created:     Friday 6 April 2018
*
* Closely modelled on example code from the IBM TSS software
*
* (C) Copyright 2018, University of Surrey, all rights reserved.
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


#include <chrono>
#include <sstream>
#include "Tpm_error.h"
#include "Tpm_defs.h"
#include "Create_daa_key.h"

/*
typedef struct {
    TPMI_DH_OBJECT              parentHandle;
    TPM2B_SENSITIVE_CREATE      inSensitive;
    TPM2B_PUBLIC                inPublic;
    TPM2B_DATA                  outsideInfo;
    TPML_PCR_SELECTION          creationPCR;
} Create_In;     
*/

/*
typedef struct {
    TPM2B_PRIVATE       outPrivate;
    TPM2B_PUBLIC        outPublic;
    TPM2B_CREATION_DATA creationData;
    TPM2B_DIGEST        creationHash;
    TPMT_TK_CREATION    creationTicket;
} Create_Out;
*/

TPM_RC create_daa_key(
	TSS_CONTEXT* tss_context,
	TPM_HANDLE parent_key_handle,
	TPMI_ECC_CURVE curve_ID,
    Create_Out* out
)
{
    TPM_RC rc=0;

    if (log_ptr->debug_level()>0)
    {
        log_ptr->os() << "create_daa_key\n";
    }

	Tpm_timer tt;

	Create_In in;
	in.parentHandle = parent_key_handle;
	/* Table 133 - Definition of TPMS_SENSITIVE_CREATE Structure <IN>sensitive  */
	/* Table 75 - Definition of Types for TPM2B_AUTH userAuth */
	in.inSensitive.sensitive.userAuth.t.size = 0;
	in.inSensitive.sensitive.data.t.size = 0;
	
	
	TPMT_PUBLIC& tpmt_public = in.inPublic.publicArea;
	tpmt_public.type = TPM_ALG_ECC;
	tpmt_public.nameAlg = TPM_ALG_SHA256;

	/* Table 32 - TPMA_OBJECT objectAttributes */
	tpmt_public.objectAttributes.val = TPMA_OBJECT_FIXEDTPM |
		TPMA_OBJECT_NODA |
		TPMA_OBJECT_FIXEDPARENT |
		TPMA_OBJECT_SENSITIVEDATAORIGIN |
		TPMA_OBJECT_RESTRICTED |
		TPMA_OBJECT_USERWITHAUTH |
		TPMA_OBJECT_SIGN;

	/* Table 181 - Definition of {ECC} TPMS_ECC_PARMS Structure eccDetail */
	/* Table 129 - Definition of TPMT_SYM_DEF_OBJECT Structure symmetric */
	/* Non-storage keys must have TPM_ALG_NULL for the symmetric algorithm */
	tpmt_public.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;

	tpmt_public.parameters.eccDetail.scheme.scheme = TPM_ALG_ECDAA;
	tpmt_public.parameters.eccDetail.scheme.details.ecdaa.hashAlg = TPM_ALG_SHA256;
	tpmt_public.parameters.eccDetail.scheme.details.ecdaa.count = 1;
	tpmt_public.parameters.eccDetail.curveID = curve_ID;
	tpmt_public.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
	/* Table 177 - TPMU_PUBLIC_ID unique */
	/* Table 177 - Definition of TPMU_PUBLIC_ID */
	tpmt_public.unique.ecc.x.t.size = 0;
	tpmt_public.unique.ecc.y.t.size = 0;

	tpmt_public.authPolicy.t.size=0;

	in.outsideInfo.t.size = 0;
	/* Table 102 - TPML_PCR_SELECTION creationPCR */
	in.creationPCR.count = 0;


	rc = TSS_Execute(tss_context,
		(RESPONSE_PARAMETERS *)out,
		(COMMAND_PARAMETERS *)&in,
		NULL,
		TPM_CC_Create,
		TPM_RS_PW, NULL, 0,
		TPM_RH_NULL, NULL, 0);
	if (rc != 0)
	{
		log_ptr->os() << "create_daa_key: " << get_tpm_error(rc) << std::endl;
        throw(Tpm_error("create daa key failed"));
	}

	tpm_timings.add("TPM2_Create",tt.get_duration());	

    return rc;
}
