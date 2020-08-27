/*******************************************************************************
* File:        Flush_context.cpp
* Description: Use TPM2_FlushContext to remove an object from transient memory
*
* Author:      Chris Newton
*
* Created:     Sunday 6 May 2018
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


#include "Tss_includes.h"
#include "Tpm_error.h"
#include "Tpm_defs.h"
#include "Flush_context.h"

TPM_RC flush_context(
TSS_CONTEXT* tssContext,
TPMI_DH_CONTEXT handle
)
{
    TPM_RC  rc = 0;

    Tpm_timer tt;

    FlushContext_In in;
    
    in.flushHandle=handle;

/*
typedef struct {
    TPMI_DH_CONTEXT     flushHandle;
} FlushContext_In;
*/    
    rc = TSS_Execute(tssContext,
                        NULL, 
                        (COMMAND_PARAMETERS *)&in,
                        NULL,
                        TPM_CC_FlushContext,
                        TPM_RH_NULL, NULL, 0);
    if (rc != 0)
    {
        log_ptr->os() << "flush_context: " << get_tpm_error(rc) << std::endl;
        throw(Tpm_error("flush context failed"));
    }
    
    tpm_timings.add("TPM2_FlushContext",tt.get_duration());

    
    return rc;
}

