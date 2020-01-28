/******************************************************************************
* File:        Flush_context.cpp
* Description: Use TPM2_FlushContext to remove an object from transient memory
*
* Author:      Chris Newton
*
* Created:     Sunday 6 May 2018
*
* (C) Copyright 2018, University of Surrey.
*
******************************************************************************/

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

